#ifndef GUI_WIDGETS_HPP
#define GUI_WIDGETS_HPP

#include <string>
#include <vector>

// Renders the controls, input fields, checkboxes, and results tables
void RenderScannerUI();

// thread-safe wrapper to add text to the log panel
void LogToConsole(const std::string& message);

#endif