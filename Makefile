NAME	:= pfe_ft_nmap
CXX	:= c++
CXXFLAGS	:= -Wall -Wextra -Wunreachable-code -std=c++17

HEADERS	:= -I ./include
LIBS	:= -lpcap -lpthread

SRCS	:= $(shell find src -type f -name "*.cpp")
OBJS	:= $(SRCS:src/%.cpp=obj/%.o)

all: $(NAME)

obj/%.o: src/%.cpp
	mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -o $@ -c $< $(HEADERS) && echo "Compiled: $(notdir $<)"

$(NAME): $(OBJS)
	$(CXX) $(OBJS) $(LIBS) $(HEADERS) -o $(NAME) && echo "Linked: $(NAME)"

clean:
	rm -rf $(OBJS) && echo "Removed: $(OBJS)"

fclean: clean
	rm -rf $(NAME) && echo "Removed: $(NAME)"

re: clean all

.PHONY: all clean fclean re
.SILENT:
