import unittest

import os
from pprint import pprint

DIR = os.environ["DIR"]
DEST = os.environ["DEST"]

import shutil
import pathlib
import logging

import uuid
import inspect
import logging
import functools
from typing import Callable


class NeedTypeAnnotationOnLoggerParameterError(Exception):
    pass


def logging_make_default_logger(
    func: Callable,
) -> Callable:
    logger_parameter_name = None
    for parameter in inspect.signature(func).parameters.values():
        if parameter.annotation is logging.Logger:
            logger_parameter_name = parameter.name
    if logger_parameter_name is None:
        raise NeedTypeAnnotationOnLoggerParameterError(func)

    module_name = inspect.getmodule(func).__name__.replace(os.path.sep, ".")

    @functools.wraps(func)
    def wraper_pass_logger_if_none(*args, **kwargs):
        if logger_parameter_name not in kwargs:
            kwargs[logger_parameter_name] = logging.getLogger(
                f"{module_name}.{func.__name__}"
            )
        return func(*args, **kwargs)

    return wraper_pass_logger_if_none


import exif
import hashlib


@logging_make_default_logger
def images_rename_by_date_directory(
    source_directory: str,
    target_directory: str,
    logger: logging.Logger = None,
):
    target_directory = pathlib.Path(target_directory).expanduser()
    if not target_directory.is_dir():
        target_directory.mkdir(parents=True)
    for image_path in pathlib.Path(source_directory).expanduser().rglob("*"):
        image_bytes = image_path.read_bytes()
        try:
            image_exif = exif.Image(image_bytes)
        except Exception as error:
            logger.error("EXIF error for %s: %s", image_path.resolve(), error)
            continue
        if not image_exif.has_exif or not hasattr(image_exif, "datetime_original"):
            logger.info("No EXIF data for %s", image_path.resolve())
            continue
        date_stem = image_exif.datetime_original.replace(":", "-").replace(" ", "-")
        date_path = pathlib.Path(
            target_directory,
            ".".join([date_stem] + image_path.suffixes),
        )
        if date_path.exists():
            date_bytes = date_path.read_bytes()
            date_hash = hashlib.sha256(date_bytes).hexdigest()
            image_hash = hashlib.sha256(image_bytes).hexdigest()
            if date_hash == image_hash:
                logger.info(
                    "Image already renamed: %s -> %s",
                    image_path.resolve(),
                    date_path.resolve(),
                )
                continue
            date_path = date_path.with_stem(f"{date_path.stem}-{uuid.uuid4()}")
        shutil.copyfile(image_path, date_path)
        logger.info(
            "Renamed image: %s -> %s", image_path.resolve(), date_path.resolve()
        )


class TestRenameByDate(unittest.TestCase):
    def test_directory(self):
        print()
        logging.basicConfig(level=logging.DEBUG)
        images_rename_by_date_directory(DIR, DEST)
