"""Robust QR decoding from camera photos and screenshots.

Uses OpenCV's QR detector with several image preprocessing variants (CLAHE,
adaptive thresholding, upscaling, sharpening, inversion, rotation). An optional
WeChat QR detector is used when its model files are present, which is notably
better on photos of curved or low-contrast codes.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import cv2
import numpy as np
from PIL import Image, ImageOps

from .config import ARTIFACTS_DIR, MAX_PAYLOAD_LENGTH

Source = Union[str, Path, bytes, bytearray, np.ndarray]

_MAX_DIM = 2600
_WECHAT_DIR = ARTIFACTS_DIR / "wechat"
_WECHAT_FILES = (
    "detect.prototxt",
    "detect.caffemodel",
    "sr.prototxt",
    "sr.caffemodel",
)


def _load_bgr(source: Source) -> np.ndarray:
    if isinstance(source, np.ndarray):
        if source.ndim == 2:
            return cv2.cvtColor(source, cv2.COLOR_GRAY2BGR)
        return source
    if isinstance(source, (bytes, bytearray)):
        img = Image.open(io.BytesIO(bytes(source)))
    else:
        img = Image.open(Path(source))
    img = ImageOps.exif_transpose(img)
    if img.mode not in ("RGB", "L"):
        img = img.convert("RGB")
    if max(img.size) > _MAX_DIM:
        img.thumbnail((_MAX_DIM, _MAX_DIM), Image.LANCZOS)
    arr = np.array(img)
    if arr.ndim == 2:
        return cv2.cvtColor(arr, cv2.COLOR_GRAY2BGR)
    return cv2.cvtColor(arr, cv2.COLOR_RGB2BGR)


def _variants(gray: np.ndarray) -> List[Tuple[str, np.ndarray, float]]:
    """Return (name, image, scale) preprocessing variants, cheapest first."""
    out: List[Tuple[str, np.ndarray, float]] = [("original", gray, 1.0)]

    h, w = gray.shape[:2]
    if min(h, w) < 700:
        up = cv2.resize(gray, (w * 2, h * 2), interpolation=cv2.INTER_CUBIC)
        out.append(("upscaled_2x", up, 2.0))
    else:
        up = gray

    clahe = cv2.createCLAHE(clipLimit=2.5, tileGridSize=(8, 8)).apply(up)
    out.append(("clahe", clahe, 2.0 if min(h, w) < 700 else 1.0))

    blur = cv2.GaussianBlur(clahe, (3, 3), 0)
    adaptive = cv2.adaptiveThreshold(
        blur, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 31, 7
    )
    out.append(("adaptive_threshold", adaptive, 2.0 if min(h, w) < 700 else 1.0))

    _, otsu = cv2.threshold(clahe, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    out.append(("otsu", otsu, 2.0 if min(h, w) < 700 else 1.0))

    sharpen_kernel = np.array([[0, -1, 0], [-1, 5, -1], [0, -1, 0]])
    sharp = cv2.filter2D(clahe, -1, sharpen_kernel)
    out.append(("sharpened", sharp, 2.0 if min(h, w) < 700 else 1.0))
    out.append(("inverted", 255 - clahe, 2.0 if min(h, w) < 700 else 1.0))
    return out


def _rotate(img: np.ndarray, angle: int) -> np.ndarray:
    if angle == 90:
        return cv2.rotate(img, cv2.ROTATE_90_CLOCKWISE)
    if angle == 180:
        return cv2.rotate(img, cv2.ROTATE_180)
    if angle == 270:
        return cv2.rotate(img, cv2.ROTATE_90_COUNTERCLOCKWISE)
    return img


def _points_to_bbox(points: Any, scale: float = 1.0,
                    origin: Tuple[int, int] = (0, 0)) -> Optional[List[List[int]]]:
    if points is None:
        return None
    arr = np.asarray(points, dtype=np.float32)
    if arr.size == 0:
        return None
    arr = arr.reshape(-1, 2) / max(scale, 1e-6)
    ox, oy = origin
    return [[int(round(x + ox)), int(round(y + oy))] for x, y in arr]


def _load_wechat():
    from .config import ARTIFACTS_DIR as _AD

    path = _AD / "wechat"
    if not all((path / name).exists() for name in _WECHAT_FILES):
        return None
    try:
        return cv2.wechat_qrcode_WeChatQRCode(
            str(path / "detect.prototxt"),
            str(path / "detect.caffemodel"),
            str(path / "sr.prototxt"),
            str(path / "sr.caffemodel"),
        )
    except Exception:
        return None


_WECHAT = _load_wechat()


def _decode_with_opencv(img: np.ndarray, detector: "cv2.QRCodeDetector",
                        variant: str, scale: float,
                        results: List[Dict], seen: set,
                        origin: Tuple[int, int] = (0, 0)) -> None:
    try:
        retval, texts, points, _ = detector.detectAndDecodeMulti(img)
    except (cv2.error, ValueError):
        retval, texts, points = False, (), None
    if retval and texts:
        for i, text in enumerate(texts):
            text = (text or "").strip()
            if not text or text.lower() in seen:
                continue
            if len(text) > MAX_PAYLOAD_LENGTH:
                text = text[:MAX_PAYLOAD_LENGTH]
            seen.add(text.lower())
            bbox = None
            if points is not None and len(points) > i:
                bbox = _points_to_bbox(points[i], scale, origin)
            results.append({
                "data": text,
                "bbox": bbox,
                "method": "opencv_multi",
                "variant": variant,
            })

    # Also try single-code decoding: on multi-code images some variants return
    # only one code from detectAndDecodeMulti, while others return the other.
    try:
        text, points, _ = detector.detectAndDecode(img)
    except (cv2.error, ValueError):
        return
    text = (text or "").strip()
    if text and text.lower() not in seen:
        if len(text) > MAX_PAYLOAD_LENGTH:
            text = text[:MAX_PAYLOAD_LENGTH]
        seen.add(text.lower())
        results.append({
            "data": text,
            "bbox": _points_to_bbox(points, scale, origin),
            "method": "opencv_single",
            "variant": variant,
        })


def _decode_with_wechat(img: np.ndarray, variant: str, scale: float,
                        results: List[Dict], seen: set,
                        origin: Tuple[int, int] = (0, 0)) -> None:
    if _WECHAT is None:
        return
    try:
        texts, points = _WECHAT.detectAndDecode(img)
    except Exception:
        return
    for i, text in enumerate(texts or []):
        text = (text or "").strip()
        if not text or text.lower() in seen:
            continue
        if len(text) > MAX_PAYLOAD_LENGTH:
            text = text[:MAX_PAYLOAD_LENGTH]
        seen.add(text.lower())
        bbox = None
        if points is not None and len(points) > i:
            bbox = _points_to_bbox(points[i], scale, origin)
        results.append({
            "data": text,
            "bbox": bbox,
            "method": "wechat",
            "variant": variant,
        })


def _mask_found(gray: np.ndarray, results: List[Dict]) -> Tuple[np.ndarray, bool]:
    """White-out decoded QR regions so the detector can find the next code.

    OpenCV's multi-detector reliably finds only one of several codes in a photo.
    Erasing a found code (plus a margin) stops it from shadowing its neighbours.
    """
    masked = gray.copy()
    h, w = masked.shape[:2]
    changed = False
    for item in results:
        bbox = item.get("bbox")
        if not bbox:
            continue
        pts = np.asarray(bbox, dtype=np.int32).reshape(-1, 2)
        x, y, bw, bh = cv2.boundingRect(pts)
        if bw <= 0 or bh <= 0:
            continue
        pad = max(10, int(0.15 * max(bw, bh)))
        cv2.rectangle(
            masked,
            (max(0, x - pad), max(0, y - pad)),
            (min(w - 1, x + bw + pad), min(h - 1, y + bh + pad)),
            255,
            -1,
        )
        changed = True
    return masked, changed


def _tiles(w: int, h: int) -> List[Tuple[int, int, int, int]]:
    """Overlapping crops that can each contain a full QR code.

    OpenCV's multi-detector frequently misses one of two codes in a photo, so
    we also scan wide/tall images in overlapping halves and square images in
    overlapping quadrants.
    """
    overlap = 0.38
    if w >= h * 1.2:
        tw = int(w * (0.5 + overlap / 2))
        xs = [(0, min(w, tw)), (max(0, w - tw), w)]
        ys = [(0, h)]
    elif h >= w * 1.2:
        th = int(h * (0.5 + overlap / 2))
        xs = [(0, w)]
        ys = [(0, min(h, th)), (max(0, h - th), h)]
    else:
        tw = int(w * (0.5 + overlap / 2))
        th = int(h * (0.5 + overlap / 2))
        xs = [(0, min(w, tw)), (max(0, w - tw), w)]
        ys = [(0, min(h, th)), (max(0, h - th), h)]
    return [(x0, y0, x1, y1) for y0, y1 in ys for x0, x1 in xs]


def decode_qr(source: Source, rotations: bool = True) -> Dict:
    """Decode every QR code found in an image.

    Returns a dict with ``payloads`` (list), ``count``, ``image`` quality info
    and an ``error`` string when no code could be read.
    """
    try:
        bgr = _load_bgr(source)
    except Exception as exc:
        return {
            "payloads": [], "count": 0,
            "image": {}, "error": f"Could not open image: {exc}",
        }

    h, w = bgr.shape[:2]
    gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
    blur_score = float(cv2.Laplacian(gray, cv2.CV_64F).var())
    brightness = float(gray.mean())
    warnings: List[str] = []
    if min(h, w) < 220:
        warnings.append("Image is very small; move closer or upload a larger image.")
    if blur_score < 45:
        warnings.append("Image looks blurry; hold the camera steady and refocus.")
    if brightness < 35:
        warnings.append("Image is very dark; add more light.")
    elif brightness > 235:
        warnings.append("Image is overexposed; reduce glare.")

    results: List[Dict] = []
    seen: set = set()
    detector = cv2.QRCodeDetector()
    variants = _variants(gray)

    # Cheap hint of how many codes are visible. OpenCV under-reports these
    # points, so it is only used to skip unnecessary extra work.
    detected_points = 0
    try:
        found, points = detector.detectMulti(gray)
        if found and points is not None:
            detected_points = len(points)
    except (cv2.error, ValueError):
        pass

    # Pass 1: preprocessing variants at the original orientation. Stop early
    # once a code is decoded and no second code is expected: the masking pass
    # below is a better way to find additional codes than more variants.
    for index, (name, img, scale) in enumerate(variants):
        _decode_with_opencv(img, detector, name, scale, results, seen)
        _decode_with_wechat(img, name, scale, results, seen)
        if results and index >= 1 and detected_points <= len(results):
            break

    # Pass 2: rotations (photos are often sideways / upside down).
    if not results and rotations:
        for angle in (90, 180, 270):
            for name, img, scale in variants[:3]:
                rot = _rotate(img, angle)
                _decode_with_opencv(rot, detector, f"{name}_rot{angle}", scale, results, seen)
                _decode_with_wechat(rot, f"{name}_rot{angle}", scale, results, seen)
                if results:
                    break
            if results:
                break

    # Pass 3: mask each decoded code and rescan for additional codes.
    for _ in range(3):
        if not results:
            break
        masked, changed = _mask_found(gray, results)
        if not changed:
            break
        before = len(results)
        for name, img, scale in _variants(masked)[:5]:
            _decode_with_opencv(img, detector, name, scale, results, seen)
            _decode_with_wechat(img, name, scale, results, seen)
        if len(results) == before:
            break

    # Pass 4: overlapping tiles. Cameras and OpenCV's multi-detector often
    # miss one code when two or more are visible in the same frame. Tiles are
    # cut from the masked image so an already-decoded code cannot spill into
    # the neighbouring tile and confuse the detector. When nothing decoded at
    # all, always try tiles; otherwise only when the detector saw extra codes.
    if len(results) < 2 and (not results or detected_points >= 2):
        masked, _ = _mask_found(gray, results)
        for x0, y0, x1, y1 in _tiles(w, h):
            tile = masked[y0:y1, x0:x1]
            if tile.size == 0 or min(tile.shape[:2]) < 60:
                continue
            for name, img, scale in _variants(tile)[:3]:
                _decode_with_opencv(img, detector, f"tile_{name}", scale,
                                    results, seen, (x0, y0))
                _decode_with_wechat(img, f"tile_{name}", scale,
                                    results, seen, (x0, y0))
            if len(results) >= 4:
                break

    return {
        "payloads": results,
        "count": len(results),
        "image": {
            "width": int(w),
            "height": int(h),
            "blur_score": round(blur_score, 2),
            "brightness": round(brightness, 2),
            "warnings": warnings,
        },
        "error": None if results else (
            "No QR code found. Try a sharper, closer photo with the full code visible."
        ),
    }
