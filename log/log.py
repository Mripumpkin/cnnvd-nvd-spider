import logging
import os
import logging.handlers
from concurrent_log_handler import ConcurrentRotatingFileHandler

#带颜色的log模块
BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)
RESET_SEQ = "\033[0m"
COLOR_SEQ = "\033[1;%dm"
BOLD_SEQ = "\033[1m"

COLORS = {
    'WARNING': YELLOW,
    'INFO': WHITE,
    'DEBUG': BLUE,
    'CRITICAL': YELLOW,
    'ERROR': RED
}

# LOG_FORMAT = "[$BOLD%(name)-15s$RESET][%(levelname)-10s][%(asctime) s]  %(message)s ($BOLD%(filename)s$RESET:%(lineno)d)"
LOG_FORMAT = "[$BOLD%(name)s$RESET][%(levelname)-10s][%(asctime) s]  %(message)s ($BOLD%(filename)s$RESET:%(lineno)d)"


LOG_PATH = os.path.join(os.getcwd(), 'logs')

class ColoredFormatter(logging.Formatter):
    def __init__(self, msg, use_color = True):
        logging.Formatter.__init__(self, msg)
        self.use_color = use_color

    def format(self, record):
        levelname = record.levelname
        if self.use_color and levelname in COLORS:
            levelname_color = COLOR_SEQ % (30 + COLORS[levelname]) + levelname + RESET_SEQ
            record.levelname = levelname_color
        return logging.Formatter.format(self, record)


class CustomLogger:
    def __init__(self, name):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)

        if not self.logger.handlers:
            color_format = self.formatter_message(LOG_FORMAT, True)
            color_formatter = ColoredFormatter(color_format)

            stream_handler = logging.StreamHandler()
            stream_handler.setFormatter(color_formatter)

            tmp_name = "Cnnvd-Nvd"
            logfile = f"{os.path.join(LOG_PATH, tmp_name)}.log"
            file_handler = ConcurrentRotatingFileHandler(logfile, "a", 5*1024*1024, 5)
            file_handler.setFormatter(color_formatter)

            self.logger.addHandler(stream_handler)
            self.logger.addHandler(file_handler)

    def formatter_message(self, message, use_color=True):
        if use_color:
            message = message.replace("$RESET", RESET_SEQ).replace("$BOLD", BOLD_SEQ)
        else:
            message = message.replace("$RESET", "").replace("$BOLD", "")
        return message
    
    def get_logger(self):
        return self.logger
