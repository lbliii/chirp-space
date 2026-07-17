"""Pillow-backed normalization for untrusted Space photo uploads."""

from __future__ import annotations

from io import BytesIO

from PIL import Image, ImageOps, UnidentifiedImageError

from chirp_space.content import MAX_IMAGE_DIMENSION, NormalizedImage, NormalizedVariant

_FORMATS = {
    "JPEG": ("image/jpeg", "jpg"),
    "PNG": ("image/png", "png"),
    "WEBP": ("image/webp", "webp"),
}
_VARIANT_WIDTHS = (("small", 480), ("medium", 1280))


class PillowImageNormalizer:
    """Decode, orient, strip metadata, and re-encode one bounded still image."""

    def normalize(self, data: bytes) -> NormalizedImage:
        try:
            with Image.open(BytesIO(data)) as probe:
                source_format = probe.format
                if source_format not in _FORMATS:
                    raise ValueError("Photo must be JPEG, PNG, or WebP.")
                self._validate_container(data, source_format)
                self._validate_probe(probe)
                probe.verify()

            with Image.open(BytesIO(data)) as decoded:
                self._validate_probe(decoded)
                decoded.load()
                oriented = ImageOps.exif_transpose(decoded)
                self._validate_dimensions(oriented.width, oriented.height)
                clean = self._pixel_only(oriented, source_format)
        except ValueError:
            raise
        except (Image.DecompressionBombError, OSError, SyntaxError, UnidentifiedImageError) as exc:
            raise ValueError("Photo could not be safely decoded.") from exc

        media_type, extension = _FORMATS[source_format]
        full = self._encode(clean, source_format)
        variants = tuple(
            self._variant(clean, source_format, name=name, width=width)
            for name, width in _VARIANT_WIDTHS
            if clean.width > width
        )
        return NormalizedImage(
            full,
            media_type,
            extension,
            clean.width,
            clean.height,
            variants,
        )

    @staticmethod
    def _validate_probe(image: Image.Image) -> None:
        PillowImageNormalizer._validate_dimensions(image.width, image.height)
        if bool(getattr(image, "is_animated", False)) or int(getattr(image, "n_frames", 1)) != 1:
            raise ValueError("Animated photos are not supported.")

    @staticmethod
    def _validate_dimensions(width: int, height: int) -> None:
        if not (1 <= width <= MAX_IMAGE_DIMENSION) or not (1 <= height <= MAX_IMAGE_DIMENSION):
            raise ValueError("Photo dimensions cannot exceed 4096 x 4096.")

    @staticmethod
    def _validate_container(data: bytes, source_format: str) -> None:
        """Reject bytes appended after the image container (a common polyglot form)."""
        if source_format == "JPEG":
            if not data.startswith(b"\xff\xd8") or not data.endswith(b"\xff\xd9"):
                raise ValueError("JPEG container has trailing or incomplete data.")
            return
        if source_format == "WEBP":
            if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"WEBP":
                raise ValueError("WebP container is invalid.")
            declared_size = int.from_bytes(data[4:8], "little") + 8
            if declared_size != len(data):
                raise ValueError("WebP container has trailing or incomplete data.")
            return
        if not data.startswith(b"\x89PNG\r\n\x1a\n"):
            raise ValueError("PNG container is invalid.")
        offset = 8
        while offset + 12 <= len(data):
            length = int.from_bytes(data[offset : offset + 4], "big")
            chunk_end = offset + 12 + length
            if chunk_end > len(data):
                raise ValueError("PNG container is incomplete.")
            chunk_type = data[offset + 4 : offset + 8]
            offset = chunk_end
            if chunk_type == b"IEND":
                if length != 0 or offset != len(data):
                    raise ValueError("PNG container has trailing data.")
                return
        raise ValueError("PNG container is incomplete.")

    @staticmethod
    def _pixel_only(image: Image.Image, source_format: str) -> Image.Image:
        has_alpha = "A" in image.getbands() or "transparency" in image.info
        mode = "RGBA" if has_alpha and source_format != "JPEG" else "RGB"
        pixels = image.convert(mode)
        clean = Image.new(mode, pixels.size)
        clean.paste(pixels)
        return clean

    @staticmethod
    def _encode(image: Image.Image, source_format: str) -> bytes:
        output = BytesIO()
        if source_format == "JPEG":
            image.save(output, "JPEG", quality=88, optimize=True, progressive=True)
        elif source_format == "PNG":
            image.save(output, "PNG", optimize=True)
        else:
            image.save(output, "WEBP", quality=88, method=4)
        return output.getvalue()

    @classmethod
    def _variant(
        cls,
        image: Image.Image,
        source_format: str,
        *,
        name: str,
        width: int,
    ) -> NormalizedVariant:
        resized = image.copy()
        resized.thumbnail((width, MAX_IMAGE_DIMENSION), Image.Resampling.LANCZOS)
        media_type, extension = _FORMATS[source_format]
        return NormalizedVariant(
            name,
            cls._encode(resized, source_format),
            media_type,
            extension,
            resized.width,
            resized.height,
        )
