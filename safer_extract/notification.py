from os.path import expanduser
from subprocess import run
from pathlib import Path
import logging

log = logging.getLogger()

# TODO use notification daemon

SFX = {
    "FAILED": expanduser(
        "~/Music/sfx/242503__gabrielaraujo__failure-wrong-action.wav"),
    "WARNING": expanduser(
        "~/Music/sfx/350860__cabled-mess__blip-c-07.wav"),
    "SUCCESS": expanduser(
        "~/Music/sfx/256113_3263906-lq.ogg")
}

def play_sound(key: str) -> None:
    """snd_path is a key in SFX dict."""
    snd_pathstr = SFX.get(key, None)
    if not snd_pathstr:
        # invalid key
        return

    snd_path = Path(snd_pathstr)
    if not snd_path.exists():
        # File specified does not exist on disk
        log.warning(f"NOTIFICATION: {key}")
        return
    run(['paplay', str(snd_path)])
