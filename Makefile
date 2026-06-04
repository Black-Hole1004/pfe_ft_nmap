NAME      := pfe_ft_nmap
GUI_NAME  := pfe_ft_nmap_gui

CXX       := c++
CXXFLAGS  := -Wall -Wextra -Wunreachable-code -std=c++17

HEADERS   := -I ./include -I ./libgui/headers -I ./libgui/imgui -I ./libgui/imgui/backends
LIBS      := -lpcap -lpthread
GUI_LIBS  := $(LIBS) -lglfw -lGL

# --- CLI Source Tracking ---
SRCS      := $(filter-out src/mainGUI.cpp, $(shell find src -type f -name "*.cpp"))
OBJS      := $(SRCS:src/%.cpp=obj/%.o)

# --- GUI Source Tracking ---
# 1. Share the backend scanner engine objects (excluding main entries)
CORE_SRCS := $(filter-out src/main.cpp src/mainGUI.cpp, $(shell find src -type f -name "*.cpp"))
CORE_OBJS := $(CORE_SRCS:src/%.cpp=obj/%.o)

# 2. Track custom interface wrappers into your obj/gui/ folder
GUI_SRCS  := $(shell find libgui/gui_src -type f -name "*.cpp")
GUI_OBJS  := $(GUI_SRCS:libgui/gui_src/%.cpp=obj/gui/%.o)

# 3. FIX: Only grab the root ImGui source files and the two exact backends needed for Linux
IMGUI_SRCS := $(shell find libgui/imgui -maxdepth 1 -type f -name "*.cpp") \
              libgui/imgui/backends/imgui_impl_glfw.cpp \
              libgui/imgui/backends/imgui_impl_opengl3.cpp
IMGUI_OBJS := $(IMGUI_SRCS:libgui/imgui/%.cpp=obj/imgui/%.o)

# Combine everything required for the GUI pipeline
ALL_GUI_OBJS := obj/mainGUI.o $(CORE_OBJS) $(GUI_OBJS) $(IMGUI_OBJS)

all: $(NAME)

# --- Rule A: Compile Core Engine sources (src/) ---
obj/%.o: src/%.cpp
	mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -o $@ -c $< $(HEADERS) && echo "Compiled Engine Core: $(notdir $<)"

# --- Rule B: Compile Custom GUI wrappers (into obj/gui/) ---
obj/gui/%.o: libgui/gui_src/%.cpp
	mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -o $@ -c $< $(HEADERS) && echo "Compiled GUI Wrapper: $(notdir $<)"

# --- Rule C: Compile Dear ImGui Library core & backends (into obj/imgui/) ---
obj/imgui/%.o: libgui/imgui/%.cpp
	mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -o $@ -c $< $(HEADERS) && echo "Compiled ImGui Component: $(notdir $<)"

# --- Linker Target: CLI ---
$(NAME): $(OBJS)
	$(CXX) $(OBJS) $(LIBS) $(HEADERS) -o $(NAME) && echo "Linked CLI Binary: $(NAME)"

# --- Linker Target: GUI ---
gui: $(GUI_NAME)

$(GUI_NAME): $(ALL_GUI_OBJS)
	$(CXX) $(ALL_GUI_OBJS) $(GUI_LIBS) $(HEADERS) -o $(GUI_NAME) && echo "Linked GUI Binary: $(GUI_NAME)"

clean:
	rm -rf obj && echo "Removed obj/ cache tree."

fclean: clean
	rm -f $(NAME) $(GUI_NAME) && echo "Removed output binaries."

re: fclean all gui

.PHONY: all gui clean fclean re
.SILENT: