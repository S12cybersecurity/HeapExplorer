#include <Windows.h>
#include <d3d11.h>
#include <imgui.h>
#include <imgui_impl_win32.h>
#include <imgui_impl_dx11.h>
#include "app.h"

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")

static ID3D11Device*            g_device    = nullptr;
static ID3D11DeviceContext*     g_context   = nullptr;
static IDXGISwapChain*          g_swapchain = nullptr;
static ID3D11RenderTargetView*  g_rtv       = nullptr;

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(
    HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

static void CreateRTV() {
    ID3D11Texture2D* back = nullptr;
    g_swapchain->GetBuffer(0, IID_PPV_ARGS(&back));
    if (back) {
        g_device->CreateRenderTargetView(back, nullptr, &g_rtv);
        back->Release();
    }
}

static LRESULT WINAPI WndProc(HWND hWnd, UINT msg,
                               WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return 1;

    switch (msg) {
    case WM_SIZE:
        if (g_device && wParam != SIZE_MINIMIZED) {
            if (g_rtv) { g_rtv->Release(); g_rtv = nullptr; }
            g_swapchain->ResizeBuffers(0, LOWORD(lParam), HIWORD(lParam),
                                        DXGI_FORMAT_UNKNOWN, 0);
            CreateRTV();
        }
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

static bool InitD3D(HWND hWnd) {
    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferCount        = 2;
    sd.BufferDesc.Format  = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferUsage        = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow       = hWnd;
    sd.SampleDesc.Count   = 1;
    sd.Windowed           = TRUE;
    sd.SwapEffect         = DXGI_SWAP_EFFECT_DISCARD;

    D3D_FEATURE_LEVEL level;
    if (FAILED(D3D11CreateDeviceAndSwapChain(
            nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
            nullptr, 0, D3D11_SDK_VERSION,
            &sd, &g_swapchain, &g_device, &level, &g_context)))
        return false;

    CreateRTV();
    return true;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int) {
    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_CLASSDC;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance      = hInstance;
    wc.lpszClassName = L"HeapExplorerGUI";
    RegisterClassExW(&wc);

    HWND hwnd = CreateWindowExW(
        0, L"HeapExplorerGUI", L"HeapExplorer",
        WS_OVERLAPPEDWINDOW,
        100, 100, 1200, 680,
        nullptr, nullptr, hInstance, nullptr);

    if (!InitD3D(hwnd)) {
        MessageBoxW(hwnd, L"Failed to initialize Direct3D 11.",
                    L"HeapExplorer", MB_OK | MB_ICONERROR);
        return 1;
    }

    ShowWindow(hwnd, SW_SHOWDEFAULT);
    UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();

    ImGui::StyleColorsDark();
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 3.0f;
    style.FrameRounding  = 2.0f;
    style.GrabRounding   = 2.0f;
    style.Colors[ImGuiCol_WindowBg] = ImVec4(0.08f, 0.08f, 0.10f, 1.0f);

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_device, g_context);

    App app;
    app.GetPipeServer().Start();

    // --attach PID from command line
    int argc = __argc;
    char** argv = __argv;
    for (int i = 1; i + 1 < argc; i++) {
        if (strcmp(argv[i], "--attach") == 0) {
            DWORD pid = (DWORD)atoi(argv[i + 1]);
            if (pid) app.AttachToPID(pid);
            break;
        }
    }

    bool running = true;
    while (running) {
        MSG msg;
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
            if (msg.message == WM_QUIT)
                running = false;
        }
        if (!running) break;

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        app.Render();

        ImGui::Render();
        const float clear[] = {0.06f, 0.06f, 0.08f, 1.0f};
        g_context->OMSetRenderTargets(1, &g_rtv, nullptr);
        g_context->ClearRenderTargetView(g_rtv, clear);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_swapchain->Present(1, 0);
    }

    app.GetPipeServer().Stop();

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    if (g_rtv)       g_rtv->Release();
    if (g_swapchain) g_swapchain->Release();
    if (g_context)   g_context->Release();
    if (g_device)    g_device->Release();

    DestroyWindow(hwnd);
    UnregisterClassW(L"HeapExplorerGUI", hInstance);
    return 0;
}
