from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from io import BytesIO

import pytest
from PIL import Image, PngImagePlugin

from chirp_space.media import PillowImageNormalizer

pytestmark = pytest.mark.issue(791)


def encoded_image(
    image_format: str,
    *,
    size: tuple[int, int] = (1600, 1200),
    metadata: bool = False,
) -> bytes:
    image = Image.new("RGB", size, (34, 139, 84))
    output = BytesIO()
    options: dict[str, object] = {}
    if image_format == "JPEG" and metadata:
        exif = Image.Exif()
        exif[274] = 6
        exif[315] = "private author"
        options["exif"] = exif
        options["comment"] = b"private comment"
    if image_format == "PNG" and metadata:
        info = PngImagePlugin.PngInfo()
        info.add_text("Comment", "private comment")
        options["pnginfo"] = info
    image.save(output, image_format, **options)
    return output.getvalue()


@pytest.mark.parametrize(
    ("image_format", "media_type", "extension"),
    [("JPEG", "image/jpeg", "jpg"), ("PNG", "image/png", "png"), ("WEBP", "image/webp", "webp")],
)
def test_normalizer_accepts_still_formats_and_builds_bounded_variants(
    image_format: str, media_type: str, extension: str
) -> None:
    result = PillowImageNormalizer().normalize(encoded_image(image_format))

    assert (result.media_type, result.extension) == (media_type, extension)
    assert (result.width, result.height) == (1600, 1200)
    assert tuple(variant.name for variant in result.variants) == ("small", "medium")
    assert tuple(variant.width for variant in result.variants) == (480, 1280)
    for data in (result.data, *(variant.data for variant in result.variants)):
        with Image.open(BytesIO(data)) as decoded:
            decoded.verify()


def test_normalizer_applies_orientation_and_strips_metadata() -> None:
    result = PillowImageNormalizer().normalize(
        encoded_image("JPEG", size=(640, 480), metadata=True)
    )

    assert (result.width, result.height) == (480, 640)
    with Image.open(BytesIO(result.data)) as decoded:
        assert not decoded.getexif()
        assert "comment" not in decoded.info

    png = PillowImageNormalizer().normalize(encoded_image("PNG", metadata=True))
    with Image.open(BytesIO(png.data)) as decoded_png:
        assert "Comment" not in decoded_png.info


def test_normalizer_rejects_animation_unsupported_dimensions_and_polyglot_bytes() -> None:
    frames = [Image.new("RGB", (10, 10), color) for color in ("red", "blue")]
    animation = BytesIO()
    frames[0].save(animation, "WEBP", save_all=True, append_images=frames[1:], duration=100)

    normalizer = PillowImageNormalizer()
    with pytest.raises(ValueError, match="Animated"):
        normalizer.normalize(animation.getvalue())
    with pytest.raises(ValueError, match="safely decoded"):
        normalizer.normalize(b"<svg xmlns='http://www.w3.org/2000/svg'></svg>")
    with pytest.raises(ValueError, match="4096"):
        normalizer.normalize(encoded_image("PNG", size=(4097, 1)))
    with pytest.raises(ValueError, match="trailing"):
        normalizer.normalize(encoded_image("JPEG") + b"<script>polyglot</script>")


def test_normalizer_is_deterministic_under_concurrent_use() -> None:
    source = encoded_image("WEBP", size=(1400, 900), metadata=True)
    normalizer = PillowImageNormalizer()

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = tuple(pool.map(normalizer.normalize, (source,) * 32))

    assert len({result.data for result in results}) == 1
    assert len({tuple(variant.data for variant in result.variants) for result in results}) == 1
