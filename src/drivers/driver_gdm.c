#include "includes.h"
#include <sys/ioctl.h>

#include "common.h"
#include "driver.h"
#include "eloop.h"
#include "priv_netlink.h"
#include "common/eapol_common.h"

#include "gdm72xx_hci.h"

#include <net/if.h>

#include "eapol_supp/eapol_supp_sm.h"
#include "../wpa_supplicant/wpa_supplicant_i.h"

#define NETLINK_WIMAX	31

				#define WLAN_EID_VENDOR_SPECIFIC   221	
				#define WPA_IE_VENDOR_TYPE 0x0050f201
				#define WPA_VERSION   1	
				
struct wpa_driver_gdm_data {
	void 	*ctx;
	char 	ifname[IFNAMSIZ + 1];
	int     ifindex;
	int		netlink_sock;
#define MAX_SCAN_RESULTS 30
	struct 	wpa_scan_res *scanres[MAX_SCAN_RESULTS];
	size_t 	num_scanres;
	u8 own_addr[ETH_ALEN];
	
	u8 bssid[ETH_ALEN];
	u8 ssid[32];
};

struct gdm_msghdr{
		be16 	type;
		be16 	length;
		u8 		data[0];
} STRUCT_PACKED;

static void wpa_driver_gdm_scan_timeout(void *eloop_ctx, void *timeout_ctx);
static void wpa_driver_gdm_netlink_send(struct wpa_driver_gdm_data *drv, u16 type, u8 *data, size_t len);

static int wpa_driver_gdm_get_bssid(void *priv, u8 *bssid)
{
	struct wpa_driver_gdm_data *drv = priv;
	
	wpa_printf(MSG_DEBUG, "GDM [%s]", __FUNCTION__);

	//os_memset(bssid, 1, ETH_ALEN);
	os_memcpy(bssid, drv->bssid, ETH_ALEN);
	
	return 0;
}

static int wpa_driver_gdm_get_ssid(void *priv, u8 *ssid)
{
	struct wpa_driver_gdm_data *drv = priv;
	
	wpa_printf(MSG_INFO, "GDM [%s]", __FUNCTION__);
	
	//ssid = (u8 *) os_strdup("FRESHTEL_Ukraine");
	os_memcpy(ssid, drv->ssid, 16);
	return 16;
}

static int wpa_driver_gdm_set_key(const char *ifname, void *priv,
				   enum wpa_alg alg, const u8 *addr,
				   int key_idx, int set_tx,
				   const u8 *seq, size_t seq_len,
				   const u8 *key, size_t key_len)
{
	wpa_printf(MSG_DEBUG, "GDM [%s]: ifname=%s priv=%p alg=%d key_idx=%d "
		   "set_tx=%d",
		   __func__, ifname, priv, alg, key_idx, set_tx);
	if (addr)
		wpa_printf(MSG_DEBUG, "   addr=" MACSTR, MAC2STR(addr));
	if (seq)
		wpa_hexdump(MSG_DEBUG, "   seq", seq, seq_len);
	if (key)
		wpa_hexdump_key(MSG_DEBUG, "   key", key, key_len);
	return 0;
}

static const u8 * wpa_driver_gdm_get_mac_addr(void *priv)
{
	struct wpa_driver_gdm_data *drv = priv;
	
	wpa_printf(MSG_DEBUG, "GDM [%s]", __func__);
	
	return drv->own_addr;
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
//		be16 	type;
//		be16 	length;
//		u8 		data[0];
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
		wpa_printf(MSG_DEBUG, "GDM [%s]: No room for the new scan "
			   "result", __FUNCTION__);
		return;
	}	
	
	u8 ssid[64];
	size_t ssid_len;
	size_t extra_len = 0;
	u8 *pos;
	int i, length;
	
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
				//extra_len += 8;
				res = os_zalloc(sizeof(*res)+extra_len);// + MAX_IE_LEN
				if (res == NULL)
					return;
				os_memcpy(res->bssid, &data[i+2], ETH_ALEN);
				res->ie_len = extra_len;
				pos = (u8 *) (res + 1);
				*pos++ = 0; /* WLAN_EID_SSID = 0 */
				*pos++ = ssid_len;
				os_memcpy(pos, ssid, ssid_len);
				//res->caps = 0x11;
				//res->caps = IEEE80211_CAP_PRIVACY;
				res->freq = 3200;
				
				//pos += ssid_len;
				//u8 buf[8] = {WLAN_EID_VENDOR_SPECIFIC, 6};
				//WPA_PUT_BE32(&buf[2],WPA_IE_VENDOR_TYPE);
				//WPA_PUT_LE16(&buf[6],WPA_VERSION);
				//os_memcpy(pos, buf, 8);
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
		//u8 *pos;
		//pos = (u8 *)msg->data;
		int i;
		
		switch (type)
		{
			case WIMAX_GET_INFO_RESULT:
			{
				for (i=0; i < length;)
				{
					//pos = *msg->data[i];
					switch(msg->data[i])
					{
						case TLV_T(T_MAC_ADDRESS):
						{
							wpa_hexdump(MSG_MSGDUMP, "tlv mac", &(msg->data[i])+2, TLV_L(T_MAC_ADDRESS));
							
							i += TLV_L(T_MAC_ADDRESS) + 2;
							break;
						}
						case TLV_T(T_SUBSCRIPTION_LIST):
						{
							i += 4;
							break;
						}
						
					}
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
				/* TODO write bsid to struct */
				os_memcpy(drv->bssid, &msg->data[7], ETH_ALEN);
				wpa_supplicant_event(drv->ctx, EVENT_ASSOC, NULL);
				break;
			}
			case WIMAX_ASSOC_COMPLETE:
			{
				/* TODO check for 0xff = fail 0x00 = ok */
				//if(&msg->data[0])
				//	wpa_supplicant_event(drv->ctx, EVENT_DISASSOC, NULL);
				//else
				//	wpa_supplicant_event(drv->ctx, EVENT_ASSOC, NULL);
				break;
			}
			case WIMAX_DISCONN_IND:
			{
				/* TODO print disconnect reason */
				wpa_supplicant_event(drv->ctx, EVENT_DISASSOC, NULL);
				break;
			}
			default:
				wpa_printf(MSG_INFO, "unused type %04x len %04x", be_to_host16(msg->type), be_to_host16(msg->length)); 
		}
		
		left -= NLMSG_ALIGN(len);
		h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));
	}

}

static void * wpa_driver_gdm_init(void *ctx, const char *ifname)
{
	struct wpa_driver_gdm_data *drv;
	struct sockaddr_nl local;
	int idx;
	
wpa_printf(MSG_INFO, "GDM [init]: ifname(%s)", ifname);

	drv = os_zalloc(sizeof(*drv));
	if (drv == NULL)
		return NULL;
		
	drv->ctx = ctx;
	os_strlcpy(drv->ifname, ifname, sizeof(drv->ifname));
	drv->ifindex = if_nametoindex(drv->ifname);
	sscanf(drv->ifname, "%d", &idx);

	os_memcpy(drv->own_addr, "\x00\x11\xa4\x80\x0d\x82", ETH_ALEN);
//os_memcpy(drv->bssid, "\x00\x01\x02\x03\x04\x05", ETH_ALEN);	
	
	drv->netlink_sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_WIMAX);
	if (drv->netlink_sock < 0) {
		wpa_printf(MSG_ERROR, "GDM [%s]: Failed to open netlink "
			   "socket: %s", __FUNCTION__, strerror(errno));
		goto error;
	}
	
	os_memset(&local, 0, sizeof(local));
	
	local.nl_family = AF_NETLINK;
	local.nl_groups = idx+1;	// ifindex+1
	local.nl_pid = getpid();

	if (bind(drv->netlink_sock, (struct sockaddr *) &local, sizeof(local)) < 0)
	{
		wpa_printf(MSG_ERROR, "GDM [%s]: Failed to bind netlink "
			   "socket: %s", __FUNCTION__, strerror(errno));
		goto error_netlink;
	}
	
	eloop_register_read_sock(drv->netlink_sock, wpa_driver_gdm_netlink_receive, drv,
				 NULL);
	
//	unsigned char buf[]={TLV_T(T_SUBSCRIPTION_LIST)};
	wpa_driver_gdm_netlink_send(drv, WIMAX_RADIO_ON, NULL, 0);	
	
	return drv;
	
error_netlink:
	close(drv->netlink_sock);
error:	
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
	
	os_free(drv);
}

static void wpa_driver_gdm_scan_timeout(void *eloop_ctx, void *timeout_ctx)
{
	wpa_printf(MSG_DEBUG, "Scan timeout - try to get results");
	wpa_supplicant_event(timeout_ctx, EVENT_SCAN_RESULTS, NULL);
}

static int wpa_driver_gdm_scan(void *priv,
				  struct wpa_driver_scan_params *params)
{
	struct wpa_driver_gdm_data *drv = priv;
	
	wpa_printf(MSG_DEBUG, "GDM [%s]", __FUNCTION__);
/*	*/
	unsigned char buf[]={W_SCAN_SPECIFIED_SUBSCRIPTION, 0xd2, 0x03, 0x00, 0x00, 0x32};
	wpa_driver_gdm_netlink_send(drv, WIMAX_SCAN, buf, sizeof(buf));
	
	eloop_cancel_timeout(wpa_driver_gdm_scan_timeout, drv, drv->ctx);
	eloop_register_timeout(45, 0, wpa_driver_gdm_scan_timeout, drv,
			       drv->ctx);
				   
	//wpa_supplicant_event(drv->ctx, EVENT_SCAN_RESULTS, NULL);			   
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
/*		*/
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
	
/*
	size_t extra_len = 0;
	extra_len += 2 + 16 + 8;
	
	struct wpa_scan_res *r = NULL;
	u8 *pos2;
	r = os_zalloc(sizeof(*r) + extra_len);
	if (r == NULL) {
		return NULL;
	}
	res->res[res->num++] = r;
	
	u8 ssid[] = "FRESHTEL_Ukraine";

	r->ie_len = extra_len;
	pos2 = (u8 *) (r + 1);
	*pos2++ = 0; //WLAN_EID_SSID
	*pos2++ = 16;
	os_memcpy(pos2, ssid, 16);
			os_memcpy(drv->ssid, ssid, 16);
	r->caps = 0x11;
	
	os_memcpy(r->bssid, "\x00\x01\x02\x03\x04\x05", ETH_ALEN);
	wpa_hexdump(MSG_MSGDUMP, "lala1", (u8 *) (r + 1), extra_len);	
	r->freq = 3200;
	pos2 += 16;
#define WLAN_EID_VENDOR_SPECIFIC   221	
#define WPA_IE_VENDOR_TYPE 0x0050f201
#define WPA_VERSION   1	
	u8 buf[8] = {WLAN_EID_VENDOR_SPECIFIC, 6};
	WPA_PUT_BE32(&buf[2],WPA_IE_VENDOR_TYPE);
	WPA_PUT_LE16(&buf[6],WPA_VERSION);
	os_memcpy(pos2, buf, 8);
	wpa_hexdump(MSG_MSGDUMP, "lala2", buf, 6);
	wpa_hexdump(MSG_MSGDUMP, "lala3", (u8 *) (r + 1), extra_len);		

	return res;	*/
}

static int wpa_driver_gdm_deauthenticate(void *priv, const u8 *addr,
					  int reason_code)
{
	wpa_printf(MSG_DEBUG, "GDM [%s]", __FUNCTION__);
	return 0;
}

static int wpa_driver_gdm_disassociate(void *priv, const u8 *addr,
					int reason_code)
{
	wpa_printf(MSG_DEBUG, "GDM [%s]", __FUNCTION__);
	return 0;
}

static int wpa_driver_gdm_set_countermeasures(void *priv, int enabled)
{
	wpa_printf(MSG_DEBUG, "GDM [%s] %d", __FUNCTION__, enabled);
	return 0;
}

static int
wpa_driver_gdm_associate(void *priv,
			   struct wpa_driver_associate_params *params)
{
	struct wpa_driver_gdm_data *drv = priv;
	
	wpa_printf(MSG_DEBUG, "GDM [%s]", __FUNCTION__);
	
	u8 buf2[] = {TLV_T(T_ENABLE_AUTH), 0x01, 0x01};
	wpa_driver_gdm_netlink_send(drv, WIMAX_SET_INFO, buf2, sizeof(buf2));
	
	u8 buf[] = {TLV_T(T_H_NSPID), 0x03, 0x00, 0x00, 0x32, TLV_T(T_V_NSPID), 0x03, 0x00, 0x00, 0x32};
	wpa_driver_gdm_netlink_send(drv, WIMAX_CONNECT, buf, sizeof(buf));
	
/*	wpa_supplicant_event(drv->ctx, EVENT_ASSOC, NULL);
	u8 data[] = {EAPOL_VERSION, IEEE802_1X_TYPE_EAP_PACKET, 0x00, 0x05, 0x01, 0x01, 0x00, 0x05, 0x01};
	drv_event_eapol_rx(drv->ctx, drv->bssid, data, sizeof(data));	*/
	
	return 0;
}

const struct wpa_driver_ops wpa_driver_gdm_ops = {
	.name = "gdm",
	.desc = "gdm72xx WiMAX driver",
	.get_bssid = wpa_driver_gdm_get_bssid,
	.get_ssid = wpa_driver_gdm_get_ssid,
	.get_mac_addr = wpa_driver_gdm_get_mac_addr,
	.send_eapol = wpa_driver_gdm_send_eapol,
	.set_key = wpa_driver_gdm_set_key,
	.init = wpa_driver_gdm_init,
	.deinit = wpa_driver_gdm_deinit,
	.set_countermeasures = wpa_driver_gdm_set_countermeasures,
	.scan2 = wpa_driver_gdm_scan,
	.get_scan_results2 = wpa_driver_gdm_get_scan_results,
	.deauthenticate = wpa_driver_gdm_deauthenticate,
	.disassociate = wpa_driver_gdm_disassociate,
	.associate = wpa_driver_gdm_associate,
//	.set_operstate = wpa_driver_gdm_set_operstate,
};