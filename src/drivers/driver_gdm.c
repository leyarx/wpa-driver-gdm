/*
 * WPA Supplicant - driver interaction with gdmwm driver (GDM72xx WiMAX chips)
 * Copyright (c) 2012, Yaroslav Levandovskiy <leyarx@gmail.com>
 * Copyright (c) 2012, Macpaul Lin <macpaul@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */
 
#include "includes.h"
#include <sys/ioctl.h>
#include "zlib.h"
#include "common.h"
#include "driver.h"
#include "eloop.h"
#include "priv_netlink.h"
#include "common/eapol_common.h"
#include "crypto/crypto.h"
#include "gdm72xx_hci.h"
#include "wm_ioctl.h"
#include <net/if.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>

#include <eap_peer/eap_config.h>
#include "eapol_supp/eapol_supp_sm.h"
#include "../wpa_supplicant/wpa_supplicant_i.h"
#include "../wpa_supplicant/config.h"
//#define NETLINK_WIMAX	31

struct gdm_subscription_list {
	u8 	name[32];
	size_t 	name_len;
	u8 	nspid[3];
	u8 	nsp_name[32];
	size_t 	nsp_name_len;
};

#define GDM_IMG_XML				0x0100
#define GDM_IMG_DEVCERT			0x0101
#define GDM_IMG_SRVROOTCA		0x0102
#define GDM_IMG_DEVROOTCA		0x0103
#define GDM_IMG_DEVSUBCA		0x0104
#define GDM_IMG_EAPPARAM		0x0105
#define GDM_IMG_SRVCAS			0x0106

#define GDM_IMG_EAPPARAM_ONAI		0x01 	/* Outer NAI */
#define GDM_IMG_EAPPARAM_PKAYPASS	0x02	/* Private Key Password */
#define GDM_IMG_EAPPARAM_INAI		0x03	/* Inner NAI */
#define GDM_IMG_EAPPARAM_INAIPASS	0x04	/* Inner NAI Password */

struct gdm_ul_image {
	u8 	*buf;
	size_t	len;
};
				
struct wpa_driver_gdm_data {
	void	*ctx;
	char	ifname[IFNAMSIZ + 1];
	int	ifindex;
	int	netlink_sock;
	int	ioctl_sock;
#define MAX_SCAN_RESULTS 30
	struct	wpa_scan_res *scanres[MAX_SCAN_RESULTS];
	size_t	num_scanres;
	u8	mac_addr[ETH_ALEN];
#define MAX_SUBSCRIPTIONS 255	
	struct	gdm_subscription_list *ss_list[MAX_SUBSCRIPTIONS];
	size_t	ss_list_len;
	
	struct	gdm_ul_image img_buf[7]; /* number of GDM_IMG_* */
//	struct	wpa_config_blob *blobs;
	
	PKCS12 *p12;
	EVP_PKEY *pkey;
	X509 *cert;
	STACK_OF(X509) *ca;
	
	u8	bssid[ETH_ALEN];
	u8	ssid[32];
	size_t	ssid_len;
};

struct gdm_msghdr{
	be16	type;
	be16	length;
	u8	data[0];
} STRUCT_PACKED;

struct gdm_imghdr{
	be16	type;
	be32	offset;
	u8	data[0];
} STRUCT_PACKED;

#define PEM_CERT_KEYWORD "CERTIFICATE"
#define PEM_PRIVATEKEY_KEYWORD "PRIVATE KEY"

typedef enum {
	PEM_CERTIFICATE,
	PEM_PRIVATE_KEY,
	DER_FORMAT,
	UNKNOWN_CERT_TYPE
} CERT_TYPE;

static void wpa_driver_gdm_scan_timeout(void *eloop_ctx, void *timeout_ctx);
static void wpa_driver_gdm_netlink_send(struct wpa_driver_gdm_data *drv, u16 type, u8 *data, size_t len);
static void wpa_driver_gdm_ioctl_send_status(struct wpa_driver_gdm_data *drv, int m, int c, int d);
static void wpa_driver_gdm_netlink_receive(int sock, void *eloop_ctx, void *sock_ctx);

/*
 * Data can consist from more then one certificate/key,
 * this function return pointer to the next certificate/key data,
 * return NULL if not found.
 */ 
static void *get_sortcert_data_next(u8 *data, int len)
{
	unsigned char p = data[len - 1];
	char *ptr;
	
	if(len <= 0)
		return NULL;
	data[len - 1] = 0;
	ptr = strstr((const char *)data, "\x2d\x0d\x0a\x2d");  // "END"
	if(ptr)
		ptr += 3;
	data[len - 1] = p;
	return ptr;
}

/*
 * Tell the encoding format and type of the certificate/key by examining if
 * there is "CERTIFICATE" or "PRIVATE KEY" in the data. If not, at least we
 * can test if the first byte is '0'.
 */
static CERT_TYPE get_sortcert_data_type(u8 *data, int len)
{
	CERT_TYPE type = UNKNOWN_CERT_TYPE;
	unsigned char p = data[len - 1];

	data[len - 1] = 0;
	if (strstr((const char *)data, PEM_CERT_KEYWORD) != NULL) {
		type = PEM_CERTIFICATE;
	} else if (strstr((const char *)data, PEM_PRIVATEKEY_KEYWORD) != NULL) {
		type = PEM_PRIVATE_KEY;
	} else if (data[0] == '0') {
		type = DER_FORMAT;
	}
	data[len - 1] = p;
	return type;
}

static void wpa_driver_gdm_sortcert_img(struct wpa_driver_gdm_data *drv, u8 *data, int len, u16 img_type)
{
	X509 *cert = NULL;
	EVP_PKEY *pkey = NULL;
	BIO *bp = NULL;
	STACK_OF(X509_NAME) *sk = drv->ca;
	CERT_TYPE type;
	u8 *ptr = data;
	int size;

	do {
		size = len - (ptr - data);
		if(size <= 0)
			goto end;
		if (size < sizeof(PEM_CERT_KEYWORD)) {
			goto end;
		}
		if (((type = get_sortcert_data_type(ptr, size)) != PEM_CERTIFICATE) &&
			(type != PEM_PRIVATE_KEY)) {
			goto end;
		}
		bp = BIO_new(BIO_s_mem());
		if (!bp) goto err;
		if (!BIO_write(bp, ptr, size)) goto err;
		if (type == PEM_CERTIFICATE) {
			if ((cert = PEM_read_bio_X509(bp, NULL, NULL, NULL)) != NULL) {
				if ( img_type == GDM_IMG_DEVCERT )
					drv->cert = cert;
				else 
				{
					if (sk == NULL)
					{
						sk = sk_X509_NAME_new_null();
						if (sk == NULL)
						{
							wpa_printf(MSG_ERROR, "Error allocate STACK_OF(X509_NAME)");
							goto err;
						}
						drv->ca = sk;
					}
					sk_X509_push(sk, cert);
				}
			}
		} else {
			if ((pkey = PEM_read_bio_PrivateKey(bp, NULL, NULL, NULL)) != NULL) {
				/* Optional image type checking */
				if ( img_type == GDM_IMG_DEVCERT ) 
					drv->pkey = pkey;				
			}
		}
err:
		if (bp) BIO_free(bp);
		
		ptr = get_sortcert_data_next(ptr, size);
	} while(ptr != NULL);
end:
	return;
}

static int wpa_driver_gdm_uncompress_img( void *data, size_t size )
{
	int fd[2];
	voidp gz;
	int len;
	
	if(pipe(fd) < 0){
		wpa_printf(MSG_ERROR, "Can't open pipe to uncompress image");	
		return -1;
	}
	len = write( fd[1], data, size);
	close(fd[1]);
	gz = gzdopen(fd[0],"rb");
	if (gz == NULL)
	{
		wpa_printf(MSG_ERROR, "Error open gz image");		
		return -1;
	}
	len = gzread(gz, data, 16384); /* 16384 max len depend on compress level "now parameter len*2 testing" */
	gzclose(gz);
		
	return len;
}

static int wpa_driver_gdm_decrypt_img(struct wpa_driver_gdm_data *drv, u8 *data, size_t len)
{
	u8 buf[len], shakey[0x18];
	const u8 *addr[1];
	size_t addr_len[1];
	addr[0] = drv->mac_addr;
	addr_len[0] = ETH_ALEN;
	void *aes_ctx;
	u8 *pos = data;
	u8 iv[16] = {0x43,0x6c,0x61,0x72,0x6b,0x4a,0x4a,0x61,0x6e,0x67,0x00,0x00,0x00,0x00,0x00,0x00}; /* ClarkJJang */
	int i, j;
	
	struct gdm_decimghdr{
	be32	len;
	u8 		data[0];
	} STRUCT_PACKED;
	
	struct gdm_decimghdr *dec_data;
	
	memset(buf, 0, sizeof(buf));
	memset(shakey, 0, sizeof(shakey));
	
	sha1_vector(1, addr, addr_len, shakey);
	
	aes_ctx = aes_decrypt_init(shakey, sizeof(shakey));
	if (aes_ctx == NULL) {
		wpa_printf(MSG_ERROR, "aes_ctx init failed");
		return -1;
	}
	
	for (i = 0; i < len / 16; i++) {
		aes_decrypt(aes_ctx, pos, pos);
		for (j = 0; j < 16; j++)
			pos[j] ^= iv[j];
		pos += 16;
	}

	aes_decrypt_deinit(aes_ctx);
	int dec_len;
	dec_data = (struct gdm_decimghdr *) data;
	dec_len = be_to_host32(dec_data->len);
	os_memmove(data, dec_data->data, dec_len);
	
	/* TODO: add check for return value */
	wpa_hexdump(MSG_MSGDUMP, "cbc_decrypt", data, dec_len);
	
	return dec_len;
}

static void wpa_driver_gdm_get_img_timeout(void *eloop_ctx, void *timeout_ctx)
{
	wpa_printf(MSG_DEBUG, "GDM [%s] Get image timeout", __FUNCTION__);
}

static void wpa_driver_gdm_get_img(struct wpa_driver_gdm_data *drv, u16 type)
{
	u8 buf[6];
	
	wpa_printf(MSG_DEBUG, "GDM [%s] (type %04x)", __FUNCTION__, type);
	
	os_memset(buf, 0, sizeof(buf));
	WPA_PUT_BE16(buf, type);
	
	eloop_register_timeout(5, 0, wpa_driver_gdm_get_img_timeout, drv,
				drv->ctx);	
	
	wpa_driver_gdm_netlink_send(drv, WIMAX_UL_IMAGE, buf, sizeof(buf));

	while(eloop_is_timeout_registered(wpa_driver_gdm_get_img_timeout, drv, drv->ctx))
	{
		eloop_wait_for_read_sock(drv->netlink_sock);
		wpa_driver_gdm_netlink_receive(drv->netlink_sock, drv, drv->ctx);
	}
}

static void wpa_driver_gdm_get_imgs(struct wpa_driver_gdm_data *drv)
{
	wpa_printf(MSG_DEBUG, "GDM [%s]", __FUNCTION__);

	wpa_driver_gdm_get_img(drv, GDM_IMG_DEVCERT);
	wpa_driver_gdm_get_img(drv, GDM_IMG_SRVROOTCA);
	wpa_driver_gdm_get_img(drv, GDM_IMG_DEVROOTCA);
	wpa_driver_gdm_get_img(drv, GDM_IMG_DEVSUBCA);
	wpa_driver_gdm_get_img(drv, GDM_IMG_SRVCAS);
	wpa_driver_gdm_get_img(drv, GDM_IMG_EAPPARAM);
}

static void wpa_driver_gdm_get_img_status(struct wpa_driver_gdm_data *drv, u16 type, u32 offset)
{
	u8 buf[10];
	
	wpa_printf(MSG_DEBUG, "GDM [%s] (type %04x) (offset %08x)", __FUNCTION__, type, offset);
	
	os_memset(buf, 0, sizeof(buf));
	WPA_PUT_BE16(buf, type);	
	WPA_PUT_BE32(buf + 2, offset);
	
	wpa_driver_gdm_netlink_send(drv, WIMAX_UL_IMAGE_STATUS, buf, sizeof(buf));
}

static void wpa_driver_gdm_get_img_result(struct wpa_driver_gdm_data *drv,
						const unsigned char *data,
						int len)
{
	struct gdm_imghdr *hdr;
	struct gdm_ul_image *img;
	u16 type;
	u32 offset;
	hdr = (struct gdm_imghdr *) data;
	type = be_to_host16(hdr->type);
	offset = be_to_host32(hdr->offset);
	img = &drv->img_buf[type & 0xff];
	
	wpa_printf(MSG_DEBUG, "GDM [%s] (type %04x) (offset %08x)", __FUNCTION__, type, offset);
	
	if (offset == 0xffffffff && img->buf == NULL)
	{
		wpa_printf(MSG_DEBUG, "Device image %04x is empty", type);
		eloop_cancel_timeout(wpa_driver_gdm_get_img_timeout, drv, drv->ctx);
		return;
	} 
	else if (offset == 0xffffffff && img->buf)
	{
		wpa_printf(MSG_DEBUG, "Device image %04x size %zu", type, img->len);	
		eloop_cancel_timeout(wpa_driver_gdm_get_img_timeout, drv, drv->ctx);
		/* TODO: decrypt, unpack, write to blob & free img buf */
						
		switch (type)
		{
			case GDM_IMG_XML:
				break;
			case GDM_IMG_DEVCERT:
			case GDM_IMG_SRVROOTCA:
			case GDM_IMG_DEVROOTCA:
			case GDM_IMG_DEVSUBCA:
			case GDM_IMG_SRVCAS:
			{
				img->len = wpa_driver_gdm_decrypt_img(drv, img->buf, img->len);
				if (img->len != -1) {
					img->len = wpa_driver_gdm_uncompress_img(img->buf, img->len);
					if (img->len != -1) {
						wpa_driver_gdm_sortcert_img(drv, img->buf, img->len, type);
					}
				}
				break;
			}
			case GDM_IMG_EAPPARAM:
			{
				img->len = wpa_driver_gdm_decrypt_img(drv, img->buf, img->len);
				/* TODO: add check for all errors when allocating memmory and generating certs */
				/* device eap parameters */
				int i, data_len;
				u8 		*data = img->buf;
				u8 		*anonymous_identity = NULL;
				size_t 	anonymous_identity_len = 0;
				u8 		*identity = NULL;	
				size_t 	identity_len = 0;
				u8 		*password = NULL;
				size_t 	password_len = 0;
				u8 		*private_key_passwd = NULL;
				/* getting access to blobs and eap parameters */
				struct wpa_supplicant * wpa_s = drv->ctx;
				struct wpa_config_blob * blobs = wpa_s->conf->blobs;
				struct wpa_config_blob * blob;
				/* creating PKCS#12 pack */
				PKCS12 			*p12 = NULL;
				char			*p12_pass = NULL;
				RSA 			*rsa = NULL;
				EVP_PKEY 		*pkey = drv->pkey;
				X509			*cert = drv->cert;
				STACK_OF(X509) 	*ca = drv->ca;
				X509_NAME 		*certn = NULL;
				/* Parse eap parameters from device memmory */
				for(i = 0; i < img->len;)
				{
					data_len = (data[i+1] << 8) + data[i+2];
					char str[data_len + 1];
					str[data_len] = '\0';
					memcpy(str, data + i + 3, data_len);
					// wpa_printf(MSG_DEBUG, "GDM [%s] Device EAPPARAM image %d : %s", __FUNCTION__, data[i], str);
					switch(data[i])
					{
						case GDM_IMG_EAPPARAM_ONAI:
							anonymous_identity = (u8 *)os_strdup(str);
							anonymous_identity_len = data_len;
							break;
						case GDM_IMG_EAPPARAM_PKAYPASS:
							private_key_passwd = (u8 *)os_strdup(str);
							break;
						case GDM_IMG_EAPPARAM_INAI:
							identity = (u8 *)os_strdup(str);
							identity_len = data_len;
							break;
						case GDM_IMG_EAPPARAM_INAIPASS:
							password = (u8 *)os_strdup(str);
							password_len = data_len;
							break;
					}
					i += 3 + data_len;		
				}
				/* If anonymous_identity is not presented in conf file then use device eap parameters */
				if(!wpa_s->conf->ssid->eap.anonymous_identity)
				{
					wpa_printf(MSG_INFO, "Using Device EAP parameters.");
					wpa_s->conf->ssid->eap.anonymous_identity = (u8 *)os_strdup((char *)anonymous_identity);
					wpa_s->conf->ssid->eap.anonymous_identity_len = anonymous_identity_len;
					wpa_s->conf->ssid->eap.identity = (u8 *)os_strdup((char *)identity);
					wpa_s->conf->ssid->eap.identity_len = identity_len;
					wpa_s->conf->ssid->eap.password = (u8 *)os_strdup((char *)password);
					wpa_s->conf->ssid->eap.password_len = password_len;		
				}
				
				if(wpa_s->conf->ssid->eap.private_key && !os_strcmp((char *) wpa_s->conf->ssid->eap.private_key, "blob://device_certs")) 
				{
					wpa_printf(MSG_INFO, "Using Device Certificates.");
					wpa_s->conf->ssid->eap.private_key_passwd = (u8 *)os_strdup((char *)private_key_passwd);
					p12_pass = (char *)wpa_s->conf->ssid->eap.private_key_passwd;
				}
							
				OpenSSL_add_all_algorithms();
				
				/* Generating fake pkey */
				if(!pkey)
				{
					wpa_printf(MSG_INFO, "Generating fake Private Key.");
					if ((rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL)) == NULL)
						wpa_printf(MSG_ERROR, "GDM [%s] Error generating RSA key.", __FUNCTION__);	
					if ((pkey = EVP_PKEY_new()) == NULL)
						wpa_printf(MSG_ERROR, "GDM [%s] Error creating EVP_PKEY structure.", __FUNCTION__);	
					if (!EVP_PKEY_assign_RSA(pkey, rsa))
						wpa_printf(MSG_DEBUG, "GDM [%s] Error assigning RSA to PKEY.", __FUNCTION__);
				}
				/* Generating fake cert */	
				if(!cert)
				{
					wpa_printf(MSG_INFO, "Generating fake Device Certificate.");
					if ((cert = X509_new()) == NULL)
						wpa_printf(MSG_ERROR, "GDM [%s] Error allocating cert.", __FUNCTION__);	
					X509_set_version(cert, 2);
					ASN1_INTEGER_set(X509_get_serialNumber(cert), 0);
					X509_gmtime_adj(X509_get_notBefore(cert), 0);
					X509_gmtime_adj(X509_get_notAfter(cert),
											  (long)60 * 60 * 24 * 365);
					if (!pkey || !X509_set_pubkey(cert, pkey))
						wpa_printf(MSG_ERROR, "GDM [%s] Error setting public key.", __FUNCTION__);
								
					certn = X509_get_subject_name(cert);
					X509_NAME_add_entry_by_txt(certn,
											  "C", MBSTRING_ASC, (u8 *) "UA", -1, -1, 0);
					X509_NAME_add_entry_by_txt(certn,
											  "O", MBSTRING_ASC, (u8 *) "yarx.org.ua", -1, -1, 0);
					X509_NAME_add_entry_by_txt(certn,
											  "CN", MBSTRING_ASC, (u8 *) "Yaroslav Levandovskiy", -1, -1, 0);		
									 
					X509_set_issuer_name(cert, certn);
					if (!X509_sign(cert, pkey, EVP_md5()))
						wpa_printf(MSG_ERROR, "GDM [%s] Error signing cert.", __FUNCTION__);
				}	

				/* Generating PKCS#12 certificate */	
				BIO *bio_err = BIO_new_fp (stderr, BIO_NOCLOSE);			
				p12 = PKCS12_create( p12_pass, "device", pkey, cert, ca,
										0, 0, 0, 0, 0);
					 
				if (!p12)
				{
					wpa_printf(MSG_ERROR, "Failed generating a valid PKCS12 certificate.");
					ERR_print_errors (bio_err);
				}
				else 
				{
					u8 *buf = NULL;
					blob = (struct wpa_config_blob *) os_zalloc (sizeof(struct wpa_config_blob));
					if(!blob)
						wpa_printf(MSG_ERROR, "GDM [%s] Error allocating memmory for blob.", __FUNCTION__);
					int buf_len = 0;
					if((buf_len = i2d_PKCS12(p12, &buf)) <= 0)
						wpa_printf(MSG_ERROR, "GDM [%s] Error converting PKCS12 certificate.", __FUNCTION__);
					if (buf) 
					{
						blob->name = os_strdup("device_certs");
						blob->data = (u8 *) os_zalloc (buf_len);
						os_memcpy(blob->data, buf, buf_len);
						os_free(buf);
						blob->len = buf_len;
						wpa_printf(MSG_DEBUG, "GDM [%s] Creating blob name %s len %lu", __FUNCTION__, blob->name, blob->len);
						if(!blobs) 
							wpa_s->conf->blobs = blob;
						else
						{
							while(blobs->next) 
							{
								wpa_printf(MSG_DEBUG, "GDM [%s] Exist blob name %s len %lu", __FUNCTION__, blobs->name, blobs->len);
								blobs = blobs->next;
							}
							blobs->next = blob;
						}
					}
				}
				
				if (rsa) RSA_free(rsa);
				if (p12) PKCS12_free(p12);
				//EVP_cleanup();
				
				break;
			}
		}
		//os_free(img->buf);
		//img->buf = NULL;
		//img->len = 0;
		return;		
	}
	else if (!offset && img->buf == NULL && len > sizeof(struct gdm_imghdr))
	{
		img->len = len - sizeof(struct gdm_imghdr);
		img->buf = (u8 *)os_zalloc(16384);
		os_memcpy(img->buf, hdr->data, img->len);
	}
	else if (offset && img->buf && len > sizeof(struct gdm_imghdr))
	{
		os_memcpy(img->buf + img->len, hdr->data, len - sizeof(struct gdm_imghdr));
		img->len += len - sizeof(struct gdm_imghdr);
	}
	
	wpa_driver_gdm_get_img_status(drv, type, offset);
}

static int wpa_driver_gdm_get_bssid(void *priv, u8 *bssid)
{
	struct wpa_driver_gdm_data *drv = priv;
	
	wpa_printf(MSG_DEBUG, "GDM [%s]", __FUNCTION__);

	os_memcpy(bssid, drv->bssid, ETH_ALEN);
	
	return 0;
}

static int wpa_driver_gdm_get_ssid(void *priv, u8 *ssid)
{
	struct wpa_driver_gdm_data *drv = priv;
	
	wpa_printf(MSG_INFO, "GDM [%s]", __FUNCTION__);
	
	os_memcpy(ssid, drv->ssid, drv->ssid_len);
	return drv->ssid_len;
}

static const u8 * wpa_driver_gdm_get_mac_addr(void *priv)
{
	struct wpa_driver_gdm_data *drv = priv;
	struct ifreq ifr;
	
	wpa_printf(MSG_DEBUG, "GDM [%s]", __func__);
	
	ifr.ifr_addr.sa_family = AF_INET;
	os_strncpy(ifr.ifr_name, drv->ifname, IFNAMSIZ-1);
	ioctl(drv->ioctl_sock, SIOCGIFHWADDR, &ifr);
	
	os_memcpy(drv->mac_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	
	return drv->mac_addr;
}

static int wpa_driver_gdm_send_eapol(void *priv, const u8 *dest, u16 proto,
				      const u8 *data, size_t data_len)
{
	struct wpa_driver_gdm_data *drv = priv;
	
	wpa_hexdump(MSG_MSGDUMP, "gdm_send_eapol TX frame", data, data_len);
	
	wpa_driver_gdm_netlink_send(drv, WIMAX_TX_EAP, 
				(u8 *)data + sizeof(struct ieee802_1x_hdr),
				data_len - sizeof(struct ieee802_1x_hdr));
	return 0;
}

static void wpa_driver_gdm_netlink_send(struct wpa_driver_gdm_data *drv, u16 type, u8 *data, size_t len)
{
	struct sockaddr_nl dest;
	struct msghdr msg;
	struct iovec iov;
	struct nlmsghdr *h = NULL;
	int size = len+4+4;
	unsigned char buf[size];
	
	struct gdm_nlmsghdr{
		le32	ifindex;
		struct 	gdm_msghdr msg;
	} STRUCT_PACKED;
	
	struct gdm_nlmsghdr *hdr;	
	
	wpa_printf(MSG_DEBUG, "GDM [%s] type: %04x len: %lu", __FUNCTION__, type, len);
	
	os_memset(&dest, 0, sizeof(dest));
	os_memset(&buf, 0, sizeof(buf));

	hdr = (struct gdm_nlmsghdr *) buf;
	hdr->ifindex = host_to_le32(drv->ifindex);
	hdr->msg.type =  host_to_be16(type);
	hdr->msg.length =  host_to_be16(len);
	
	if (data)
		os_memcpy(hdr->msg.data, data, len);
	
	wpa_hexdump(MSG_MSGDUMP, "send msg", buf, size);
	
	h = (struct nlmsghdr *)os_zalloc(NLMSG_SPACE(size));
    os_memset(h, 0, NLMSG_SPACE(size));
    h->nlmsg_len = NLMSG_LENGTH(size);
    h->nlmsg_pid = getpid();
    h->nlmsg_flags = 0;
//wpa_printf(MSG_DEBUG, "size: %d NLMSG_SPACE(size): %d NLMSG_LENGTH(size) %d", size, NLMSG_SPACE(size), NLMSG_LENGTH(size));
	os_memcpy(NLMSG_DATA(h), buf, sizeof(buf));
	dest.nl_family = AF_NETLINK;
    dest.nl_pid = 0;   /* For Linux Kernel */
    dest.nl_groups = 0; /* unicast */
    iov.iov_base = (void *)h;
    iov.iov_len = h->nlmsg_len;
	os_memset(&msg,0,sizeof(msg));
	msg.msg_name = (void *)&dest;
    msg.msg_namelen = sizeof(dest);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
	
//	wpa_hexdump(MSG_MSGDUMP, "nlmsghdr", h, NLMSG_SPACE(size));
	
	if(sendmsg(drv->netlink_sock,&msg,0) < 0)
	{
		wpa_printf(MSG_INFO, "GDM [%s]: send failed: %s",
			__FUNCTION__, strerror(errno));
	}
}

static void wpa_driver_gdm_netlink_receive_rx_eap(struct wpa_driver_gdm_data *drv,
						const unsigned char *data,
						int len)
{
	struct ieee802_1x_hdr *hdr;
	
	wpa_printf(MSG_DEBUG, "GDM [%s] len = %d", __FUNCTION__, len);

	hdr = os_zalloc(sizeof(*hdr)+len);
	hdr->version = EAPOL_VERSION;
	hdr->type = IEEE802_1X_TYPE_EAP_PACKET;
	hdr->length = host_to_be16(len);
	os_memcpy(hdr+1, data, len);
	wpa_hexdump(MSG_MSGDUMP, "receive_rx_eap -> hdr", (u8 *) hdr, sizeof(*hdr)+len);
	drv_event_eapol_rx(drv->ctx, drv->bssid, (u8 *) hdr, sizeof(*hdr)+len);
	
	struct wpa_supplicant *wpa_s = drv->ctx;
	u8 key[64];
	//int key_len = eapol_sm_get_key(wpa_s->eapol, key, sizeof(key));
	if(!eapol_sm_get_key(wpa_s->eapol, key, sizeof(key)))
	{
		wpa_printf(MSG_DEBUG, "GDM [%s] EAP Success", __func__);
		u8 buf[sizeof(key)+2] = {TLV_T(T_MSK),sizeof(key)};
		os_memcpy(buf+2, key, sizeof(key));
		wpa_driver_gdm_netlink_send(drv, WIMAX_SET_INFO, buf, sizeof(buf));
	}
}

static void wpa_driver_gdm_scanresp(struct wpa_driver_gdm_data *drv,
						const unsigned char *data,
						int len)
{
	struct wpa_scan_res *res;
	
	wpa_printf(MSG_DEBUG, "GDM [%s] len = %d", __FUNCTION__, len);

	if (drv->num_scanres >= MAX_SCAN_RESULTS) {
		wpa_printf(MSG_ERROR, "GDM [%s]: No room for the new scan "
			   "result", __FUNCTION__);
		return;
	}	
	
	u8 ssid[64];
	size_t ssid_len;
	size_t extra_len = 0;
	u8 *pos;
	int i;
	
	for (i=0; i < len;)
	{
		switch(data[i])
		{
			case TLV_T(T_H_NSPID):
				break;
			case TLV_T(T_V_NSPID):
				break;	
			case TLV_T(T_NSP_NAME):
				ssid_len = data[i+1];
				os_memcpy(ssid, &data[i+2], ssid_len);
				extra_len += 2 + ssid_len;
				break;
			case TLV_T(T_BSID):
				if (res)
				{
					os_free(drv->scanres[drv->num_scanres]);
					drv->scanres[drv->num_scanres++] = res;
					res = NULL;
				}
				res = os_zalloc(sizeof(*res)+extra_len);// + MAX_IE_LEN
				if (res == NULL)
					return;
				os_memcpy(res->bssid, &data[i+2], ETH_ALEN);
				res->ie_len = extra_len;
				pos = (u8 *) (res + 1);
				*pos++ = 0; /* WLAN_EID_SSID = 0 */
				*pos++ = ssid_len;
				os_memcpy(pos, ssid, ssid_len);
				//res->freq = 3200;
				break;
			case TLV_T(T_CINR):
				if(res)
					res->noise = data[i+2];
				break;						
			case TLV_T(T_RSSI):
				if(res)
					res->level = data[i+2]-0x100;
				break;
		}
		i += data[i+1] + 2;
		wpa_printf(MSG_DEBUG, "GDM [%s] i = %d", __FUNCTION__, i);
	}

	if (res)
	{
		os_free(drv->scanres[drv->num_scanres]);
		drv->scanres[drv->num_scanres++] = res;
	}
}

static void wpa_driver_gdm_netlink_receive(int sock, void *eloop_ctx, void *sock_ctx)
{
	struct wpa_driver_gdm_data *drv = eloop_ctx;
	char buf[8192];
	int left;
	struct sockaddr_nl from;
	socklen_t fromlen;
	struct nlmsghdr *h;
	
	wpa_printf(MSG_DEBUG, "GDM [%s]", __FUNCTION__);
	
	fromlen = sizeof(struct sockaddr_nl);
	left = recvfrom(sock, buf, sizeof(buf), MSG_DONTWAIT,
		(struct sockaddr *) &from, &fromlen);
	if (left < 0) {
		if (errno != EINTR && errno != EAGAIN)
			wpa_printf(MSG_INFO, "GDM [%s]: recvfrom failed: %s",
				   __FUNCTION__, strerror(errno));
		return;
	}
	
	for (h = (struct nlmsghdr*) buf; left >= (ssize_t)sizeof(*h); ) {
		int len = h->nlmsg_len;
		int l = len - sizeof(*h);	
		
		if ((l < 0) || (len > left)) {
			wpa_printf(MSG_INFO, "GDM [%s]: wrong msg len: %d",
				   __FUNCTION__, len);
			continue;
		}	
		wpa_hexdump(MSG_MSGDUMP, "receive netlink msg", NLMSG_DATA(h), NLMSG_PAYLOAD(h, 0));

		struct 	gdm_msghdr *msg;
		msg = (struct gdm_msghdr *)NLMSG_DATA(h);
		u16 type = be_to_host16(msg->type);
		u16 length = be_to_host16(msg->length);
		int i;
		
		switch (type)
		{
			case WIMAX_GET_INFO_RESULT:
			{
				struct gdm_subscription_list *list;
				for (i=0; i < length;)
				{
					
					//pos = *msg->data[i];
					switch(msg->data[i])
					{
						case TLV_T(T_H_NSPID):
						{
							if (list) { 
								os_free(drv->ss_list[drv->ss_list_len]);
								drv->ss_list[drv->ss_list_len++] = list;
								list = NULL;
							}
							list = os_zalloc(sizeof(*list));
							if (list == NULL)
								return;
							os_memcpy(list->nspid, &msg->data[i+2], msg->data[i+1]);
							break;
						}
						case TLV_T(T_NSP_NAME):
						{
							if (list) {
								if (list->nsp_name_len != 0) {
									wpa_printf(MSG_DEBUG, "GDM [%s] list->nsp_name %s already exists! list->nsp_name_len: %lu",
										__FUNCTION__, list->nsp_name, list->nsp_name_len);
									break;
								}
								os_memcpy(list->nsp_name, &msg->data[i+2], msg->data[i+1]);
								list->nsp_name_len = msg->data[i+1];
								wpa_printf(MSG_INFO, "Home Network SSID \"%s\"", list->nsp_name);
							}
							break;
						}
						case TLV_T(T_SUBSCRIPTION_NAME):
						{
							if (list) {
								os_memcpy(list->name, &msg->data[i+2], msg->data[i+1]);
								list->name_len = msg->data[i+1];
							}					
							break;
						}
						/*
						case TLV_T(T_SUBSCRIPTION_LIST):
						{
							i += 4;
							break;
						}
						*/
					}
					if (msg->data[i] == TLV_T(T_SUBSCRIPTION_LIST))
						i += 4;
					else
						i += 2 + msg->data[i+1];
				}
				if (list) {
					os_free(drv->ss_list[drv->ss_list_len]);
					drv->ss_list[drv->ss_list_len++] = list;
					list = NULL;
				}
				break;
			}
			case WIMAX_SCAN_RESULT:
			{
				if(length == 0)
					break;
				wpa_driver_gdm_scanresp(drv, msg->data, length);				
				break;
			}
			case WIMAX_SCAN_COMPLETE:
			{
				eloop_cancel_timeout(wpa_driver_gdm_scan_timeout, drv, drv->ctx);
				wpa_supplicant_event(drv->ctx, EVENT_SCAN_RESULTS, NULL);
				break;
			}
			case WIMAX_RX_EAP:
			{
				wpa_driver_gdm_netlink_receive_rx_eap(drv, msg->data, length);
				break;
			}
			case WIMAX_ASSOC_START:
			{
				wpa_driver_gdm_ioctl_send_status(drv, M_CONNECTING, C_ASSOCSTART, D_INIT);
				/* TODO write bsid to struct */
				os_memcpy(drv->bssid, &msg->data[7], ETH_ALEN);
				wpa_supplicant_event(drv->ctx, EVENT_ASSOC, NULL);
				break;
			}
			case WIMAX_ASSOC_COMPLETE:
			{
				/* TODO check for 0xff == fail and fill wpa_event_data::assoc_reject*/
				if(msg->data[0])
					wpa_supplicant_event(drv->ctx, EVENT_ASSOC_REJECT , NULL);
				else
					wpa_driver_gdm_ioctl_send_status(drv, M_CONNECTING, C_ASSOCCOMPLETE, D_INIT);
				break;
			}
			case WIMAX_CONNECT_COMPLETE:
			{
				if(msg->data[0])
					wpa_driver_gdm_ioctl_send_status(drv, M_INIT, C_INIT, D_INIT);
				else
					wpa_driver_gdm_ioctl_send_status(drv, M_CONNECTED, C_CONNCOMPLETE, D_INIT);
				break;
			}
			case WIMAX_DISCONN_IND:
			{
				wpa_driver_gdm_ioctl_send_status(drv, M_INIT, C_INIT, D_INIT);
				/* TODO print disconnect reason */
				wpa_supplicant_event(drv->ctx, EVENT_DISASSOC, NULL);
				break;
			}
			case WIMAX_UL_IMAGE_RESULT:
			{
				wpa_driver_gdm_get_img_result(drv, msg->data, length);
				break;
			}
			default:
				wpa_printf(MSG_DEBUG, "unused type %04x len %04x", be_to_host16(msg->type), be_to_host16(msg->length)); 
		}
		
		left -= NLMSG_ALIGN(len);
		h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));
	}

}

static void wpa_driver_gdm_ioctl_send_status(struct wpa_driver_gdm_data *drv, int m, int c, int d)
{
	struct wm_req_s req;
	struct fsm_s set;
	
	wpa_printf(MSG_DEBUG, "GDM [%s] (main status %d) (connection status %d) (oma-dm status %d)",
						__FUNCTION__, m, c, d);

	os_strncpy(req.ifr_ifrn.ifrn_name, drv->ifname, IFNAMSIZ-1);
	req.cmd = SIOCS_DATA;
	req.data_id = SIOC_DATA_FSM;
	req.data.size = sizeof(struct fsm_s);
	set.m_status = m;
	set.c_status = c; 
	set.d_status = d;
	req.data.buf = &set;
	
	if (ioctl(drv->ioctl_sock, SIOCWMIOCTL, &req) == -1)
		wpa_printf(MSG_ERROR, "Failed to send status");
}

static void * wpa_driver_gdm_init(void *ctx, const char *ifname)
{
	struct wpa_driver_gdm_data *drv;
	struct sockaddr_nl local;
	int idx;
	
	wpa_printf(MSG_DEBUG, "GDM [%s]: ifname(%s)", __FUNCTION__ , ifname);

	drv = os_zalloc(sizeof(*drv));
	if (drv == NULL)
		return NULL;
		
	drv->ctx = ctx;
	os_strlcpy(drv->ifname, ifname, sizeof(drv->ifname));
	drv->ifindex = if_nametoindex(drv->ifname);
	sscanf(drv->ifname, "%d", &idx);
	
	drv->ioctl_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (drv->ioctl_sock < 0) {
		wpa_printf(MSG_ERROR, "GDM [%s]: Failed to open ioctl "
			   "socket: %s", __FUNCTION__, strerror(errno));
		goto error_ioctl;
	}
	
	drv->netlink_sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_WIMAX);
	if (drv->netlink_sock < 0) {
		wpa_printf(MSG_ERROR, "GDM [%s]: Failed to open netlink "
			   "socket: %s", __FUNCTION__, strerror(errno));
		goto error_netlink;
	}
	
	os_memset(&local, 0, sizeof(local));
	
	local.nl_family = AF_NETLINK;
	local.nl_groups = 1;	// ifindex+1 idx+1
	local.nl_pid = getpid();

	if (bind(drv->netlink_sock, (struct sockaddr *) &local, sizeof(local)) < 0)
	{
		wpa_printf(MSG_ERROR, "GDM [%s]: Failed to bind netlink "
			   "socket: %s", __FUNCTION__, strerror(errno));
		goto error;
	}
	
	if (eloop_register_read_sock(drv->netlink_sock, wpa_driver_gdm_netlink_receive
					, drv, NULL))
	{
		wpa_printf(MSG_ERROR, "GDM [%s]: Failed to register netlink "
			   "socket handler: %s", __FUNCTION__, strerror(errno));		
		goto error;
	}
	
	wpa_driver_gdm_ioctl_send_status(drv, M_INIT, C_INIT, D_INIT);
	
	/* Get subscription list from modem memory */
	u8 buf[]={TLV_T(T_SUBSCRIPTION_LIST)};
	wpa_driver_gdm_netlink_send(drv, WIMAX_GET_INFO, buf, sizeof(buf));	

	/* TODO: get cert files from modem memory and put them to wpa_config_blob's*/
	wpa_driver_gdm_get_mac_addr(drv);
	wpa_driver_gdm_get_imgs(drv);
	
	wpa_driver_gdm_netlink_send(drv, WIMAX_RADIO_ON, NULL, 0);	
	
	return drv;
	
error:
	close(drv->netlink_sock);	
error_netlink:
	close(drv->ioctl_sock);
error_ioctl:
	return NULL;
}

static void wpa_driver_gdm_deinit(void *priv)
{
	struct wpa_driver_gdm_data *drv = priv;
	
	wpa_printf(MSG_DEBUG, "GDM [%s]", __FUNCTION__);

	if (drv->netlink_sock >= 0) {
		eloop_cancel_timeout(wpa_driver_gdm_scan_timeout, drv, drv->ctx);
		wpa_driver_gdm_netlink_send(drv, WIMAX_RADIO_OFF, NULL, 0);
		eloop_unregister_read_sock(drv->netlink_sock);
		close(drv->netlink_sock);
	}
	
	if (drv->ioctl_sock >= 0)
		close(drv->ioctl_sock);
		
	if (drv->cert) X509_free(drv->cert);
	if (drv->pkey) EVP_PKEY_free(drv->pkey);	
	
	os_free(drv);
}

static void wpa_driver_gdm_scan_timeout(void *eloop_ctx, void *timeout_ctx)
{
	wpa_printf(MSG_DEBUG, "GDM [%s] Scan timeout - try to get results", __FUNCTION__);
	wpa_supplicant_event(timeout_ctx, EVENT_SCAN_RESULTS, NULL);
}

static int wpa_driver_gdm_scan(void *priv,
				  struct wpa_driver_scan_params *params)
{
	struct wpa_driver_gdm_data *drv = priv;
	struct wpa_driver_scan_ssid *ssid;
	
	wpa_printf(MSG_DEBUG, "GDM [%s]", __FUNCTION__);
	/* TODO: free() all *scanres, otherwise memory leak can occur */
	drv->num_scanres = 0; 

	ssid = &params->ssids[0];
	unsigned char buf[ssid->ssid ? (ssid->ssid_len + 3) : 1];
	if (ssid->ssid == NULL) 
	{
		buf[0] = W_SCAN_ALL_SUBSCRIPTION;
	} else {
		buf[0] = W_SCAN_SPECIFIED_SUBSCRIPTION;
		buf[1] = TLV_T(T_NSP_NAME);
		buf[2] = ssid->ssid_len;
		os_memcpy(buf + 3, ssid->ssid, ssid->ssid_len);
	}
	wpa_driver_gdm_netlink_send(drv, WIMAX_SCAN, buf, sizeof(buf));
	wpa_driver_gdm_ioctl_send_status(drv, M_SCAN, C_INIT, D_INIT);
	
	eloop_cancel_timeout(wpa_driver_gdm_scan_timeout, drv, drv->ctx);
	eloop_register_timeout(90, 0, wpa_driver_gdm_scan_timeout, drv,
				drv->ctx);	   
	return 0;
}

static struct wpa_scan_results *
wpa_driver_gdm_get_scan_results(void *priv)
{
	struct wpa_driver_gdm_data *drv = priv;
	struct wpa_scan_results *res;
	size_t i;
//drv->num_scanres = 1;
	wpa_printf(MSG_DEBUG, "GDM [%s] num_scanres %lu", __FUNCTION__, drv->num_scanres);
	
	res = os_zalloc(sizeof(*res));
	if (res == NULL) {
		return NULL;
	}	

	res->res = os_zalloc(drv->num_scanres *
			     sizeof(struct wpa_scan_res *));
	if (res->res == NULL) {
		os_free(res);
		return NULL;
	}	

	for (i = 0; i < drv->num_scanres; i++) {
		struct wpa_scan_res *r;
		if (drv->scanres[i] == NULL)
			continue;
		r = os_malloc(sizeof(*r) + drv->scanres[i]->ie_len);
		if (r == NULL)
			break;
		os_memcpy(r, drv->scanres[i],
			  sizeof(*r) + drv->scanres[i]->ie_len);
		res->res[res->num++] = r;
	}

	return res;	
}

static int wpa_driver_gdm_disassociate(void *priv, const u8 *addr,
					int reason_code)
{
	struct wpa_driver_gdm_data *drv = priv;
	
	wpa_printf(MSG_DEBUG, "GDM [%s]", __FUNCTION__);
	
	wpa_driver_gdm_netlink_send(drv, WIMAX_NET_DISCONN, NULL, 0);
	return 0;
}

static int wpa_driver_gdm_associate(void *priv,
			   struct wpa_driver_associate_params *params)
{
	struct wpa_driver_gdm_data *drv = priv;
	size_t i;
	
	wpa_printf(MSG_DEBUG, "GDM [%s]", __FUNCTION__);
	
	for(i = 0; i < drv->ss_list_len; i++)
		if (drv->ss_list[i]->nsp_name_len == params->ssid_len && 
				!os_memcmp(drv->ss_list[i]->nsp_name, params->ssid, params->ssid_len))
		{
			os_memcpy(drv->ssid, params->ssid, params->ssid_len);
			drv->ssid_len = params->ssid_len;
			u8 buf2[] = {TLV_T(T_ENABLE_AUTH), TLV_L(T_ENABLE_AUTH), 0x01};
			wpa_driver_gdm_netlink_send(drv, WIMAX_SET_INFO, buf2, sizeof(buf2));
			wpa_driver_gdm_ioctl_send_status(drv, M_CONNECTING, C_CONNSTART, D_INIT);
			u8 buf[] = {TLV_T(T_H_NSPID), TLV_L(T_H_NSPID), 0x00, 0x00, 0x00, TLV_T(T_V_NSPID), TLV_L(T_V_NSPID), 0x00, 0x00, 0x00};
			os_memcpy(&buf[2], drv->ss_list[i]->nspid, TLV_L(T_H_NSPID));
			os_memcpy(&buf[7], drv->ss_list[i]->nspid, TLV_L(T_H_NSPID)); /* TODO: use T_V_NSPID */
			wpa_driver_gdm_netlink_send(drv, WIMAX_CONNECT, buf, sizeof(buf));
			return 0;
		}
	drv->ssid_len = 0;
	return -1;
}

const struct wpa_driver_ops wpa_driver_gdm_ops = {
	.name = "gdm",
	.desc = "gdm72xx WiMAX driver",
	.get_bssid = wpa_driver_gdm_get_bssid,
	.get_ssid = wpa_driver_gdm_get_ssid,
	.get_mac_addr = wpa_driver_gdm_get_mac_addr,
	.send_eapol = wpa_driver_gdm_send_eapol,
	.init = wpa_driver_gdm_init,
	.deinit = wpa_driver_gdm_deinit,
	.scan2 = wpa_driver_gdm_scan,
	.get_scan_results2 = wpa_driver_gdm_get_scan_results,
	.disassociate = wpa_driver_gdm_disassociate,
	.associate = wpa_driver_gdm_associate,
};
