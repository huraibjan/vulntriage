#!/usr/bin/env python3
"""Generate every comic frame from the character reference (skips frames that exist).

    python art/generate_frames.py [frame_id ...]
"""
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ART = Path(__file__).resolve().parent
GEN = ART / "generated"
REF = GEN / "maya_reference.png"

STYLE = """Use the attached character reference sheet. Draw the SAME woman, Maya: medium-brown skin, dark brown hair in a low bun with loose strands, round thin-framed glasses, teal cardigan over a white top, navy trousers, navy flat shoes, a lanyard with an ID badge. Where the scene includes the assistant robot, draw the SAME small desk robot from the reference (rounded off-white body, teal accents, dark display face with two simple eyes).

Style: semi-realistic vector illustration, identical to the reference: clean flat colour shapes with two-tone shading, natural proportions, well-drawn hands, soft shadows, no heavy black outlines, no glossy 3D, no anime, no photorealism. Limited palette: ink navy #1B2233, teal #12A594, alert red #E5484D, amber #F5A524, blue #3E63DD, warm greys, wood tones. Setting: a calm modern security operations office.

This is ONE comic panel: a full-bleed illustration that fills the whole image. No panel border, no caption, no speech bubbles, no title, no watermark. Do not draw the character twice. Any text that the scene asks for must be spelled exactly as written, in a clean sans-serif, and no other text may appear anywhere.

Scene: """

L, SQ = "1536x1024", "1024x1024"
FRAMES = {
    "01_cover": (L, "Night. Wide cinematic view of the office. Maya sits at her desk in the RIGHT third of the image, seen in three-quarter view from slightly behind, typing, lit by two monitors showing rows of small red and grey alert lines (no readable text). The small assistant robot sits on the desk. A city skyline at night through a window on the far right. The LEFT half of the image is a calm, empty, deep navy wall in shadow with nothing on it, because a title will be placed there. No text anywhere."),
    "02a_arrive": (SQ, "Morning. Maya walks into the office holding a takeaway coffee, a bag on her shoulder, warm window light. On a large wall display behind her a single big counter reads exactly \"40,000+\" and nothing else."),
    "02b_all_red": (SQ, "Maya seated at her desk, seen over her shoulder in three-quarter view, looking worried, one hand on her forehead. Her large monitor shows a list of eight rows; every row ends in an identical red tag that reads exactly \"CRITICAL\". A stack of papers and a second coffee cup on the desk."),
    "02c_few_real": (SQ, "Close-up from above of a wide desk covered with a neat grid of about one hundred small identical pale grey file cards. Exactly three of the cards are bright alert red. Maya's hand holding a pen enters from the lower right corner and hovers, undecided. No face visible. No text."),
    "03a_score": (L, "Maya seated at her desk in three-quarter view, leaning toward the monitor with a skeptical expression, chin resting on her hand. The monitor shows only one very large number that reads exactly \"0.94\" with a small label above it that reads exactly \"EPSS\". Three yellow sticky notes are stuck along the edge of the monitor, each with a single large question mark."),
    "03b_board": (L, "Daylight. Maya stands at a corkboard, pinning the last of four large sticky notes arranged two by two. The notes read exactly \"RQ1\" (teal note), \"RQ2\" (red note), \"RQ3\" (amber note), \"RQ4\" (blue note). She looks focused. Nothing else is written anywhere."),
    "04_pipeline": (L, "Maya stands at the left end of a long whiteboard, marker in hand, smiling, gesturing along it. On the whiteboard, drawn in marker, five boxes in one row joined by arrows, labelled exactly \"SOURCES\", \"EVIDENCE\", \"RANK\", \"EXPLAIN\", \"DECIDE\" in that order. The small assistant robot stands on a stool below the fourth box. No other writing."),
    "05_testset": (L, "Maya stands at a large table holding a magnifying glass over a big heap of pale grey file cards in which only a few bright red cards are visible, like needles in a haystack. Behind her, tall archive shelves full of file boxes recede into depth, and a wall calendar page reads exactly \"JUNE 2024\". She looks focused."),
    "06a_win": (L, "Morning light. Maya at her desk raises a fist in celebration, smiling broadly, her chair rolled slightly back. Her monitor shows a simple horizontal bar chart with five bars: the bottom bar is long and teal and clearly longer than the grey and blue bars above it. No numbers or text on the chart. The assistant robot on the desk looks happy."),
    "07a_date": (L, "Evening, low warm light. Maya leans in close to her monitor with a skeptical, suspicious expression, pointing at the screen with a pen. The monitor shows two large lines of text: the first reads exactly \"published 2024\" and the second reads exactly \"score observed 2026\", with the \"2026\" circled in red marker. A cold coffee cup with no steam."),
    "08a_audit": (SQ, "Maya stands in side profile facing a board on the right of the image. With the arm that is nearer to the viewer she holds a magnifying glass up to a tall printed list pinned to the board; her fingers wrap naturally around the handle with the thumb resting on top of the handle, and that hand is anatomically correct for that arm, with five fingers. Her other arm hangs relaxed at her side, mostly hidden behind her body. The list is about ten short grey lines with no readable text. Seen through the lens, two of the lines glow alert red with a small red droplet mark beside them. She looks focused, having found something."),
    "09a_brief": (L, "Maya stands at her desk reading a single printed page that the small assistant robot on the desk has just handed her. On the page are three short lines, each ending with a small green tick stamp (no readable text). A rubber stamp and ink pad sit on the desk. She looks calm and satisfied; the robot looks happy."),
    "10a_ask_twice": (L, "Maya seated, arms crossed, turned toward the small assistant robot on her desk with a questioning, skeptical look. The robot looks unsure and holds up three blank cards: one card has a teal tick on it, the other two are greyed out and being put down. No text."),
    "11a_servers": (L, "A server room. Maya walks along a row of four tall server racks, holding a tablet, looking focused. Three racks have calm small teal status lights. One rack is lit with alert red lights and has a small red tag hanging from it. Cool light, clean floor reflections. No text."),
    "12a_sbom": (L, "Maya at her desk holds a very long printed paper list that trails down onto the floor, full of short grey lines with no readable text. Her monitor shows a short tidy list of only four rows; the top two rows carry a red tag and the other two are grey. She looks focused and relieved. No readable text."),
    "13a_limits": (L, "Maya stands beside a whiteboard, facing the viewer, with a small honest shrug and a calm expression, a marker in one hand. On the whiteboard are four empty checkbox squares in a column, each followed by a wavy marker line standing in for text. None of the boxes is ticked. No readable text."),
    "14a_sunrise": (L, "Sunrise, warm amber sky through the large office window. Maya stands by the window holding a fresh coffee, relaxed and smiling, looking back toward her desk. On the desk the monitor shows a short tidy list with one red row at the top and four calm grey rows. The assistant robot on the desk looks happy. No readable text."),
    "15a_thanks": (L, "Daylight. Maya stands in the office facing the viewer, smiling warmly and waving with one hand. Her desk with the monitor and the small assistant robot, which also waves, is beside her on the left. Open, uncluttered wall space on the right side of the image. No text."),
}


def run(frame_id: str) -> str:
    size, scene = FRAMES[frame_id]
    out = GEN / f"{frame_id}.png"
    if out.exists():
        return f"{frame_id}: exists"
    prompt = GEN / f"prompt_{frame_id}.txt"
    prompt.write_text(STYLE + scene)
    r = subprocess.run([sys.executable, str(ART / "gen_image.py"), str(out), size, str(prompt), str(REF)],
                       capture_output=True, text=True)
    return f"{frame_id}: {'ok' if r.returncode == 0 else 'FAILED ' + (r.stderr or r.stdout)[-300:]}"


if __name__ == "__main__":
    ids = sys.argv[1:] or list(FRAMES)
    with ThreadPoolExecutor(max_workers=5) as pool:
        for line in pool.map(run, ids):
            print(line, flush=True)
