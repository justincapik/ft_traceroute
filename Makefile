NAME		=	ft_traceroute

CC			=	gcc

##
##		FILE DESCRIPTOR
##

INCLUDE = includes libft

SRC_PATH = srcs

SRCS =	main.c			\
		parsing.c		\
		lookups.c		\
		packets.c		\
		loop.c			


##
##		SETTING VPATH
##

vpath %.c $(foreach dir, $(SRC_PATH), $(dir):)


##
##		DEPENDENCE DESCRIPTOR
##

IDEP = includes/ft_traceroute.h

OBJ_PATH = objs

OBJS = $(addprefix $(OBJ_PATH)/, $(SRCS:.c=.o))

##
##		LIB DESCRIPTOR
##

LIBFT_PATH	=	libft
LIBNAME		=	ft
LIBPATH		=	$(LIBFT_PATH)
LIBHEAD		=	$(LIBFT_PATH)

##
##		FLAGS CONSTRUCTION
##

CFLAGS += -Wall -Wextra -Werror 

IFLAGS = 	$(foreach dir, $(INCLUDE), -I$(dir) ) \

LFLAGS =	$(foreach path, $(LIBPATH), -L$(path) ) \
			$(foreach lib, $(LIBNAME), -l$(lib) ) \



$(OBJ_PATH)/%.o:	%.c $(IDEP)
	$(CC) -c $< -o $@ $(CFLAGS) $(IFLAGS)


all:		$(NAME)

$(NAME):	$(OBJ_PATH) $(OBJS)
	cd $(LIBPATH) && $(MAKE)
	$(CC) -o $(NAME) $(OBJS) $(CFLAGS) $(LFLAGS) $(IFLAGS)

clean:
	make clean -C $(LIBFT_PATH)
	rm -rf $(OBJ_PATH)

fclean: clean
	make fclean -C $(LIBFT_PATH)
	rm -rf $(NAME)

$(OBJ_PATH):
	mkdir $(OBJ_PATH)

re:			fclean all

.SILENT:	all $(NAME) fclean clean re 
.PHONY:		clean fclean re