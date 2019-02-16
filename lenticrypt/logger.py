import logging

from .utils import ANSI_BOLD, ANSI_COLOR, ANSI_RESET, CGAColors


LEVEL_COLORS = {
    logging.CRITICAL: CGAColors.MAGENTA,
    logging.ERROR: CGAColors.RED,
    logging.WARNING: CGAColors.YELLOW,
    logging.INFO: CGAColors.GREEN,
    logging.DEBUG: CGAColors.CYAN,
    logging.NOTSET: CGAColors.BLUE
}

DEFAULT_FORMAT = '$RESET$LEVELCOLOR$BOLD%(levelname)-8s$RESET %(message)s'


class ComposableFormatter(object):
    def __init__(self, *args, **kwargs):
        if len(args) == 1 and not isinstance(args[0], str):
            self._parent_formatter = args[0]
        else:
            self._parent_formatter = self.new_formatter(*args, **kwargs)

    def new_formatter(self, *args, **kwargs):
        return logging.Formatter(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._parent_formatter, name)


class ColorFormatter(ComposableFormatter):
    def __init__(self, *args, **kwargs):
        if 'use_color' in kwargs:
            self._use_color = kwargs['use_color']
            del kwargs['use_color']
        else:
            self._use_color = True
        super().__init__(*args, **kwargs)

    def reformat(self, fmt):
        for color in CGAColors:
            fmt = fmt.replace("$%s" % color.name, ANSI_COLOR % (30 + color.value))
        fmt = fmt.replace('$RESET', ANSI_RESET)
        fmt = fmt.replace('$BOLD', ANSI_BOLD)
        return fmt

    @staticmethod
    def remove_color(fmt):
        for color in CGAColors:
            fmt = fmt.replace("$%s" % color.name, '')
        fmt = fmt.replace('$RESET', '')
        fmt = fmt.replace('$BOLD', '')
        fmt = fmt.replace('$LEVELCOLOR', '')
        return fmt

    def new_formatter(self, fmt, *args, **kwargs):
        if 'datefmt' in kwargs:
            kwargs['datefmt'] = self.reformat(kwargs['datefmt'])
        return super().new_formatter(self.reformat(fmt), *args, **kwargs)

    def format(self, *args, **kwargs):
        if args[0].levelno == logging.INFO or not self._use_color:
            return args[0].getMessage()
        levelcolor = LEVEL_COLORS.get(args[0].levelno, LEVEL_COLORS[logging.NOTSET])
        ret = self._parent_formatter.format(*args, **kwargs)
        ret = ret.replace('$LEVELCOLOR', ANSI_COLOR % (30 + levelcolor.value))
        ret = ret.replace('\n', self.reformat('$RESET $BOLD$BLUE\\$RESET\n'), 1)
        ret = ret.replace('\n', self.reformat('\n$RESET$BOLD$BLUE> $RESET'))
        return ret
