import socket
import sys
import threading
import time

import pygame

from tcp_by_size import send_with_size, recv_by_size

# Initialize Pygame
pygame.init()

# Stop the program event (used when server closed connection)
STOP_EVENT = pygame.USEREVENT + 1

# Screen settings
WIDTH, HEIGHT = 800, 600
screen = pygame.display.set_mode((WIDTH, HEIGHT))
pygame.display.set_caption("Tor Client UI")

# Load and resize images
onion_logo = pygame.transform.scale(pygame.image.load("images/onion_logo.png"), (200, 200))
tor_logo = pygame.transform.scale(pygame.image.load("images/tor_logo.png"), (300, 120))

# Fonts and colors
font = pygame.font.SysFont("Arial", 30)
small_font = pygame.font.SysFont("Arial", 24)
tiny_font = pygame.font.SysFont("Arial", 20)
purple = (128, 0, 128)
light_purple = (200, 160, 255)
white = (255, 255, 255)
black = (0, 0, 0)

# Input boxes and buttons
input_box_ip = pygame.Rect(250, 230, 300, 40)
input_box_port = pygame.Rect(250, 280, 300, 40)
input_box_msg = pygame.Rect(250, 330, 300, 40)
send_button = pygame.Rect(600, 330, 100, 40)
start_button = pygame.Rect(300, 500, 200, 50)

# Default values
ip_text = '127.0.0.1'
port_text = '1234'
msg_text = ''
active_ip = False
active_port = False
active_msg = False

# States
start_screen = True
message_log = []
MAX_LOG_LINES = 9

# Business logic
SEPERATOR = '~'
NEW_CLIENT = "CLIENT"
NEW_MESSAGE = "LETTER"


def draw_start_screen():
    screen.fill(purple)
    screen.blit(tor_logo, (250, 100))
    pygame.draw.rect(screen, white, start_button, border_radius=10)
    text = font.render("Start", True, purple)
    screen.blit(text, (start_button.x + 65, start_button.y + 10))


def draw_main_screen():
    screen.fill(light_purple)
    screen.blit(onion_logo, (WIDTH // 2 - 100, 30))

    # Draw input boxes
    pygame.draw.rect(screen, white, input_box_ip, border_radius=5)
    pygame.draw.rect(screen, white, input_box_port, border_radius=5)
    pygame.draw.rect(screen, white, input_box_msg, border_radius=5)
    pygame.draw.rect(screen, purple, send_button, border_radius=5)

    # Draw input text
    ip_surface = small_font.render(ip_text, True, black)
    port_surface = small_font.render(port_text, True, black)
    msg_surface = small_font.render(msg_text, True, black)
    screen.blit(ip_surface, (input_box_ip.x + 5, input_box_ip.y + 5))
    screen.blit(port_surface, (input_box_port.x + 5, input_box_port.y + 5))
    screen.blit(msg_surface, (input_box_msg.x + 5, input_box_msg.y + 5))

    # Labels
    ip_label = small_font.render("Target IP:", True, black)
    port_label = small_font.render("Port:", True, black)
    msg_label = small_font.render("Message:", True, black)
    screen.blit(ip_label, (input_box_ip.x - 100, input_box_ip.y + 5))
    screen.blit(port_label, (input_box_port.x - 100, input_box_port.y + 5))
    screen.blit(msg_label, (input_box_msg.x - 100, input_box_msg.y + 5))

    # Send button text
    send_text = small_font.render("Send", True, white)
    screen.blit(send_text, (send_button.x + 20, send_button.y + 8))

    # Message log
    log_y = 390
    screen.blit(small_font.render("Incoming Messages:", True, black), (20, log_y))
    log_box = pygame.Rect(20, log_y + 40, 760, 160)
    pygame.draw.rect(screen, white, log_box)
    for i, line in enumerate(message_log[-MAX_LOG_LINES:]):  # put only 9 messages at a time in message log
        log_surface = tiny_font.render(line, True, black)
        screen.blit(log_surface, (log_box.x + 5, log_box.y + 5 + i * 16))


def wrap_message(message, line_length=100):
    return [message[i:i+line_length] for i in range(0, len(message), line_length)]


def receive_thread(sock):
    while True:
        try:
            data = recv_by_size(sock)
            if data == b'':
                break
            data = data.decode()
            for line in wrap_message(data):
                message_log.append(line)
        except Exception as e:
            message_log.append(f"Error: {e}")
            message_log.append("Exiting program")
            time.sleep(3)
            pygame.event.post(pygame.event.Event(STOP_EVENT))
            break


def main():
    global start_screen, ip_text, msg_text, active_ip, active_msg, active_port, port_text
    try:
        srv_ip = input("Enter Tor server ip: ")
        port = 9001
        sock = socket.socket()
        sock.connect((srv_ip, port))
        send_with_size(sock, NEW_CLIENT.encode())

        threading.Thread(target=receive_thread, args=(sock,), daemon=True).start()
    except Exception as e:
        print(f"Couldn't connect to main server: {e}")
        sys.exit()

    while True:
        for event in pygame.event.get():
            if event.type == pygame.QUIT or event.type == STOP_EVENT:
                pygame.quit()
                sys.exit()

            if start_screen:
                if event.type == pygame.MOUSEBUTTONDOWN and start_button.collidepoint(event.pos):
                    start_screen = False
            else:
                if event.type == pygame.MOUSEBUTTONDOWN:
                    active_ip = input_box_ip.collidepoint(event.pos)
                    active_port = input_box_port.collidepoint(event.pos)
                    active_msg = input_box_msg.collidepoint(event.pos)
                    if send_button.collidepoint(event.pos):
                        to_send = NEW_MESSAGE + SEPERATOR + ip_text + SEPERATOR + port_text + SEPERATOR + msg_text
                        send_with_size(sock, to_send.encode())
                        msg_text = ''  # reset the message box

                if event.type == pygame.KEYDOWN:
                    if active_ip:
                        ip_text = ip_text[:-1] if event.key == pygame.K_BACKSPACE else ip_text + event.unicode
                    elif active_port:
                        port_text = port_text[:-1] if event.key == pygame.K_BACKSPACE else port_text + event.unicode
                    elif active_msg:
                        msg_text = msg_text[:-1] if event.key == pygame.K_BACKSPACE else msg_text + event.unicode

        if start_screen:
            draw_start_screen()
        else:
            draw_main_screen()
        pygame.display.flip()


if __name__ == "__main__":
    main()
