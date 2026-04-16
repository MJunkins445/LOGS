import logging

import main


def _clear_handlers(logger):
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()


def test_setup_logging_is_idempotent():
    logger = logging.getLogger("logs")
    _clear_handlers(logger)
    try:
        configured = main.setup_logging()
        assert configured is logger
        assert len(configured.handlers) == 2

        configured = main.setup_logging()
        assert configured is logger
        assert len(configured.handlers) == 2

        handler_types = sorted(type(handler).__name__ for handler in configured.handlers)
        assert handler_types == ["FileHandler", "StreamHandler"]
    finally:
        _clear_handlers(logger)

