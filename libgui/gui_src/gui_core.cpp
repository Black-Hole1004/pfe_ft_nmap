#include "gui_core.hpp"
#include "gui_widgets.hpp"
#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"

#include <iostream>
#include <GLFW/glfw3.h>

/*
 * GUI Widget Layout Engine
 * Integrates with Dear ImGui (MIT License - Omar Cornut)
 */

// Error fallback callback for GLFW
static void glfw_error_callback(int error, const char* description) {
    std::cerr << "[-] GLFW Error " << error << ": " << description << std::endl;
}

int init_gui_window() {
    // 1. Setup GLFW window context
    glfwSetErrorCallback(glfw_error_callback);
    if (!glfwInit()) {
        std::cerr << "[-] Failed to initialize GLFW" << std::endl;
        return 1;
    }

    // Target OpenGL Profile: Version 3.0 Core (WSL friendly)
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);

    // Create window
    GLFWwindow* window = glfwCreateWindow(1280, 720, "pfe_ft_nmap - Advanced Port Scanner", nullptr, nullptr);
    if (!window) {
        std::cerr << "[-] Failed to create GLFW window" << std::endl;
        glfwTerminate();
        return 1;
    }
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1); // Enable VSync

    // 2. Initialize Dear ImGui Context
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard; // Enable keyboard controls

    // Apply dark color theme profile
    ImGui::StyleColorsDark();

    // 3. Initialize Platform/Renderer Backends
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 130");

    // Clear Color state tracking (Dark Slate)
    ImVec4 clear_color = ImVec4(0.10f, 0.10f, 0.12f, 1.00f);

    // 4. Infinite Engine Frame Redraw Loop
    while (!glfwWindowShouldClose(window)) {
        // Poll input events (mouse, keyboard, window scaling)
        glfwPollEvents();

        // Start the Dear ImGui frame session
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        // Call the scanning widgets dashboard layout
        RenderScannerUI();

        // Rendering assembly pipeline
        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(clear_color.x * clear_color.w, clear_color.y * clear_color.w, clear_color.z * clear_color.w, clear_color.w);
        glClear(GL_COLOR_BUFFER_BIT);

        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
    }

    // 5. Cleanup Resources on Close
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}