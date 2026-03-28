from __future__ import annotations

from dataclasses import dataclass

from manim import *


BG = ManimColor("#07131f")
PANEL = ManimColor("#0f2235")
PANEL_ALT = ManimColor("#143048")
PANEL_GLOW = ManimColor("#214969")
TEXT = ManimColor("#eff6ff")
MUTED = ManimColor("#8fb0c9")
GRID = ManimColor("#173046")
TEAL = ManimColor("#44d2c0")
BLUE = ManimColor("#58a6ff")
GOLD = ManimColor("#f4b860")
RED = ManimColor("#ff6f6f")
GREEN = ManimColor("#4ee39d")
YELLOW = ManimColor("#ffd36d")
ORANGE = ManimColor("#ff9961")

TOOL_STACK = [
    ("uv resolve", TEAL),
    ("PyPI + OSV", BLUE),
    ("bandit", ORANGE),
    ("secrets", YELLOW),
    ("SBOM", ManimColor("#73d2ff")),
    ("heuristics", ManimColor("#ae8dff")),
]


@dataclass
class Layout:
    terminal: VGroup
    sandbox: VGroup
    stage_card: VGroup
    evidence_bus: VGroup
    codex_core: VGroup
    tool_chips: list[VGroup]
    rich_card: VGroup
    report_card: VGroup
    gate_card: VGroup
    ingress_arrow: VMobject
    summary_arrow: VMobject
    report_arrow: VMobject
    install_arrow: VMobject


def label(text: str, size: int, color: str = TEXT, weight: str = MEDIUM, font: str = "Avenir Next") -> Text:
    return Text(text, font=font, font_size=size, color=color, weight=weight)


def shield_icon(size: float = 0.32, color: str = TEAL) -> VMobject:
    return Polygon(
        [-0.55, 0.58, 0],
        [0.55, 0.58, 0],
        [0.52, -0.04, 0],
        [0.0, -0.62, 0],
        [-0.52, -0.04, 0],
        fill_color=color,
        fill_opacity=1,
        stroke_width=0,
    ).scale(size)


def cube_icon(size: float = 0.26, color: str = BLUE) -> VMobject:
    front = RoundedRectangle(width=1.0, height=0.88, corner_radius=0.12, fill_color=color, fill_opacity=0.95, stroke_width=0)
    top = Polygon(
        [-0.5, 0.44, 0],
        [0.0, 0.76, 0],
        [0.5, 0.44, 0],
        [0.0, 0.14, 0],
        fill_color=interpolate_color(BLUE_E, color, 0.45),
        fill_opacity=1,
        stroke_width=0,
    )
    right = Polygon(
        [0.5, 0.44, 0],
        [0.5, -0.44, 0],
        [0.0, -0.74, 0],
        [0.0, 0.14, 0],
        fill_color=interpolate_color(BLUE_D, color, 0.5),
        fill_opacity=1,
        stroke_width=0,
    )
    return VGroup(front, top, right).scale(size)


def spark_icon(size: float = 0.34, color: str = GOLD) -> VMobject:
    points = [
        [0.0, 0.85, 0],
        [0.22, 0.22, 0],
        [0.82, 0.0, 0],
        [0.22, -0.2, 0],
        [0.0, -0.85, 0],
        [-0.22, -0.2, 0],
        [-0.82, 0.0, 0],
        [-0.22, 0.22, 0],
    ]
    return Polygon(*points, fill_color=color, fill_opacity=1, stroke_width=0).scale(size)


def doc_icon(size: float = 0.32, color: str = TEAL) -> VGroup:
    page = RoundedRectangle(width=1.02, height=1.26, corner_radius=0.12, fill_color=color, fill_opacity=0.15, stroke_color=color, stroke_width=2)
    fold = Polygon([0.1, 0.63, 0], [0.51, 0.63, 0], [0.51, 0.22, 0], fill_color=color, fill_opacity=0.9, stroke_width=0)
    lines = VGroup(*[
        Line(LEFT * 0.28, RIGHT * 0.27, stroke_width=3, color=color).shift(UP * y)
        for y in (0.2, -0.02, -0.24)
    ])
    return VGroup(page, fold, lines).scale(size)


def terminal_icon(size: float = 0.34, color: str = GREEN) -> VGroup:
    body = RoundedRectangle(width=1.2, height=0.92, corner_radius=0.18, fill_color=color, fill_opacity=0.12, stroke_color=color, stroke_width=2)
    prompt = VGroup(
        Line(LEFT * 0.24, ORIGIN, stroke_width=3, color=color),
        Line(ORIGIN, LEFT * 0.24 + DOWN * 0.16, stroke_width=3, color=color),
        Line(LEFT * 0.02 + DOWN * 0.16, RIGHT * 0.23 + DOWN * 0.16, stroke_width=3, color=color),
    )
    return VGroup(body, prompt).scale(size)


def brand_badge(title: str, subtitle: str, icon: VMobject, accent: str, width: float = 2.75) -> VGroup:
    shell = RoundedRectangle(
        width=width,
        height=1.05,
        corner_radius=0.26,
        fill_color=PANEL_ALT,
        fill_opacity=0.98,
        stroke_color=accent,
        stroke_width=2.2,
    )
    rail = RoundedRectangle(
        width=0.64,
        height=1.05,
        corner_radius=0.26,
        fill_color=interpolate_color(BLACK, accent, 0.32),
        fill_opacity=1,
        stroke_width=0,
    ).align_to(shell, LEFT)
    icon.move_to(rail)
    title_text = label(title, 24, TEXT, BOLD)
    subtitle_text = label(subtitle, 14, MUTED)
    stack = VGroup(title_text, subtitle_text).arrange(DOWN, aligned_edge=LEFT, buff=0.05)
    stack.next_to(rail, RIGHT, buff=0.2)
    stack.align_to(shell, UP).shift(DOWN * 0.15)
    return VGroup(shell, rail, icon, stack)


def soft_panel(width: float, height: float, accent: str, title_text: str, subtitle_text: str | None = None) -> VGroup:
    panel = RoundedRectangle(
        width=width,
        height=height,
        corner_radius=0.3,
        fill_color=PANEL,
        fill_opacity=0.96,
        stroke_color=accent,
        stroke_width=2.4,
    )
    glow = RoundedRectangle(
        width=width,
        height=height,
        corner_radius=0.3,
        stroke_color=accent,
        stroke_width=8,
        stroke_opacity=0.08,
        fill_opacity=0,
    )
    title_group = [label(title_text, 22, TEXT, BOLD)]
    if subtitle_text:
        title_group.append(label(subtitle_text, 13, MUTED))
    header = VGroup(*title_group).arrange(DOWN, aligned_edge=LEFT, buff=0.06)
    header.next_to(panel.get_top(), DOWN, buff=0.24).align_to(panel, LEFT).shift(RIGHT * 0.24)
    return VGroup(glow, panel, header)


def tool_chip(name: str, accent: str) -> VGroup:
    shell = RoundedRectangle(
        width=1.82,
        height=0.58,
        corner_radius=0.18,
        fill_color=interpolate_color(PANEL, accent, 0.12),
        fill_opacity=1,
        stroke_color=accent,
        stroke_width=1.8,
    )
    dot = Circle(radius=0.08, fill_color=accent, fill_opacity=1, stroke_width=0).align_to(shell, LEFT).shift(RIGHT * 0.2)
    text = label(name, 16, TEXT, SEMIBOLD).move_to(shell)
    text.shift(RIGHT * 0.1)
    return VGroup(shell, dot, text)


def fake_report_table() -> VGroup:
    bars = VGroup()
    ys = [0.54, 0.23, -0.08, -0.39]
    widths = [1.95, 1.62, 1.72, 1.14]
    colors = [TEAL, BLUE, YELLOW, GREEN]
    for y, width, color in zip(ys, widths, colors):
        bar = RoundedRectangle(width=width, height=0.16, corner_radius=0.08, fill_color=color, fill_opacity=0.88, stroke_width=0)
        bar.shift(UP * y + LEFT * 0.45)
        bars.add(bar)
    grid = VGroup(*[
        Line(LEFT * 1.45 + UP * y, RIGHT * 1.8 + UP * y, stroke_color=GRID, stroke_width=1.2)
        for y in (0.72, 0.39, 0.06, -0.27, -0.6)
    ])
    return VGroup(grid, bars)


def fake_terminal_rows() -> VGroup:
    lines = VGroup()
    rows = [
        ("resolve", TEAL, 1.46),
        ("scan", BLUE, 1.28),
        ("Codex", GOLD, 1.06),
        ("report", GREEN, 0.96),
    ]
    y = 0.0
    for text, color, width in rows:
        dot = Dot(radius=0.05, color=color).shift(LEFT * 1.05 + UP * y)
        bar = RoundedRectangle(width=width, height=0.13, corner_radius=0.06, fill_color=color, fill_opacity=0.78, stroke_width=0)
        bar.shift(RIGHT * 0.48 + UP * y)
        label_text = label(text, 12, TEXT).next_to(dot, RIGHT, buff=0.14)
        label_text.align_to(bar, UP)
        lines.add(dot, label_text, bar)
        y -= 0.28
    return lines


class PipGuardArchitectureAnimation(MovingCameraScene):
    def construct(self) -> None:
        self.camera.background_color = BG
        backdrop = self.build_backdrop()
        self.add(backdrop)

        title = VGroup(
            label("pip-guard runtime architecture", 44, TEXT, BOLD),
            label("scan first, let Codex decide, then gate the install", 22, MUTED),
        ).arrange(DOWN, buff=0.14)
        title.to_edge(UP, buff=0.38)

        strap = label("presentation flow", 16, GOLD, BOLD)
        strap.next_to(title[0], LEFT, buff=0.28).shift(UP * 0.02)

        self.play(FadeIn(title, shift=UP * 0.18), FadeIn(strap, shift=RIGHT * 0.2), run_time=1.1)
        self.wait(0.4)

        layout = self.build_layout()

        self.play(FadeIn(layout.terminal, shift=RIGHT * 0.3), run_time=0.9)
        self.play(FadeIn(layout.sandbox, shift=UP * 0.25), run_time=1.0)
        self.play(GrowArrow(layout.ingress_arrow), run_time=0.8)
        self.play(
            ShowPassingFlash(layout.ingress_arrow.copy().set_stroke(TEAL, width=8), time_width=0.25),
            Flash(layout.stage_card, color=TEAL, line_length=0.25),
            run_time=1.0,
        )
        self.wait(0.2)

        self.play(self.camera.frame.animate.move_to(layout.sandbox).set(width=8.8), run_time=1.25)
        tool_animations = [FadeIn(chip, shift=DOWN * 0.12) for chip in layout.tool_chips]
        self.play(
            FadeIn(layout.stage_card, shift=UP * 0.16),
            FadeIn(layout.evidence_bus, shift=UP * 0.12),
            FadeIn(layout.codex_core, scale=0.85),
            LaggedStart(*tool_animations, lag_ratio=0.12),
            run_time=1.8,
        )

        stage_pulse_arrows = self.make_stage_pulses(layout.stage_card, layout.tool_chips)
        tool_codex_arrows = self.make_codex_arrows(layout.tool_chips, layout.evidence_bus, layout.codex_core)
        self.play(*[Create(arrow) for arrow in stage_pulse_arrows], run_time=0.8)
        self.play(
            *[ShowPassingFlash(arrow.copy().set_stroke(TEAL, width=6), time_width=0.25) for arrow in stage_pulse_arrows],
            run_time=1.2,
        )
        self.play(*[Create(arrow) for arrow in tool_codex_arrows], run_time=0.8)
        self.play(
            AnimationGroup(
                *[ShowPassingFlash(arrow.copy().set_stroke(GOLD, width=6), time_width=0.25) for arrow in tool_codex_arrows],
                Flash(layout.codex_core, color=GOLD, line_length=0.22),
                lag_ratio=0.0,
            ),
            run_time=1.3,
        )
        self.wait(0.3)

        self.play(self.camera.frame.animate.move_to(ORIGIN).set(width=14.2), run_time=1.35)
        self.play(
            FadeIn(layout.rich_card, shift=LEFT * 0.24),
            FadeIn(layout.report_card, shift=RIGHT * 0.24),
            FadeIn(layout.gate_card, shift=DOWN * 0.24),
            run_time=1.2,
        )
        self.play(
            Create(layout.summary_arrow),
            Create(layout.report_arrow),
            Create(layout.install_arrow),
            run_time=0.8,
        )
        self.play(
            ShowPassingFlash(layout.summary_arrow.copy().set_stroke(BLUE, width=7), time_width=0.2),
            ShowPassingFlash(layout.report_arrow.copy().set_stroke(TEAL, width=7), time_width=0.2),
            ShowPassingFlash(layout.install_arrow.copy().set_stroke(GREEN, width=7), time_width=0.2),
            run_time=1.1,
        )

        install_copy = label("install exact scanned version", 20, GREEN, BOLD)
        install_copy.next_to(layout.gate_card, DOWN, buff=0.18)
        self.play(FadeIn(install_copy, shift=UP * 0.1), run_time=0.6)
        self.wait(0.5)

        cleanup = self.make_cleanup_overlay(layout.sandbox)
        cleanup_note = VGroup(
            label("sandbox clear-down", 26, TEXT, BOLD),
            label("artifacts fade, scratch space clears, runner idles for the next job", 16, MUTED),
        ).arrange(DOWN, aligned_edge=LEFT, buff=0.08)
        cleanup_note.next_to(layout.sandbox, DOWN, buff=0.34).align_to(layout.sandbox, LEFT)

        fade_targets = VGroup(layout.stage_card, layout.evidence_bus, *layout.tool_chips, *stage_pulse_arrows, *tool_codex_arrows)
        self.play(
            fade_targets.animate.set_opacity(0.16),
            layout.codex_core.animate.set_opacity(0.35).scale(0.92),
            FadeIn(cleanup, scale=0.88),
            FadeIn(cleanup_note, shift=UP * 0.12),
            run_time=1.3,
        )
        self.wait(0.2)

        pulse = Annulus(inner_radius=0.52, outer_radius=0.68, color=BLUE, stroke_width=0, fill_opacity=0.18).move_to(cleanup[1])
        self.play(FadeIn(pulse), run_time=0.4)
        self.play(pulse.animate.scale(1.8).set_opacity(0), run_time=1.1)
        self.remove(pulse)

        final_line = label("scan first. install second.", 30, TEXT, BOLD)
        final_line.to_edge(DOWN, buff=0.28)
        self.play(FadeIn(final_line, shift=UP * 0.1), run_time=0.7)
        self.wait(1.3)

    def build_backdrop(self) -> VGroup:
        grid = NumberPlane(
            x_range=[-8, 8, 1],
            y_range=[-4.5, 4.5, 1],
            background_line_style={
                "stroke_color": GRID,
                "stroke_opacity": 0.22,
                "stroke_width": 1,
            },
            faded_line_ratio=4,
        )
        wash = Rectangle(width=16, height=9, fill_color=BG, fill_opacity=0.84, stroke_width=0)
        orbs = VGroup(
            Circle(radius=2.2, fill_color=TEAL, fill_opacity=0.06, stroke_width=0).shift(LEFT * 5.4 + UP * 2.4),
            Circle(radius=1.8, fill_color=ORANGE, fill_opacity=0.05, stroke_width=0).shift(RIGHT * 5.0 + UP * 2.8),
            Circle(radius=1.6, fill_color=BLUE, fill_opacity=0.05, stroke_width=0).shift(RIGHT * 1.8 + DOWN * 2.5),
        )
        return VGroup(grid, wash, orbs)

    def build_layout(self) -> Layout:
        terminal = self.build_terminal_card().move_to(LEFT * 4.5 + UP * 0.72)

        sandbox = soft_panel(
            width=5.35,
            height=4.72,
            accent=BLUE,
            title_text="Daytona sandbox",
            subtitle_text="security checker",
        ).move_to(LEFT * 0.22 + UP * 0.08)
        sandbox_shell = sandbox[1]
        dashed = DashedVMobject(
            RoundedRectangle(width=5.47, height=4.84, corner_radius=0.32),
            num_dashes=40,
            color=interpolate_color(BLUE, WHITE, 0.18),
            dashed_ratio=0.55,
            stroke_width=1.4,
        ).move_to(sandbox_shell)
        sandbox.add(dashed)

        stage_card = self.build_stage_card().move_to(sandbox_shell.get_top() + DOWN * 1.08)
        evidence_bus = self.build_evidence_bus().move_to(sandbox_shell.get_center() + DOWN * 0.98)
        codex_core = self.build_codex_core().move_to(sandbox_shell.get_center() + DOWN * 1.56)

        tool_chips = []
        offsets = [
            LEFT * 1.28 + UP * 0.56,
            RIGHT * 1.28 + UP * 0.56,
            LEFT * 1.28 + DOWN * 0.08,
            RIGHT * 1.28 + DOWN * 0.08,
            LEFT * 1.28 + DOWN * 0.72,
            RIGHT * 1.28 + DOWN * 0.72,
        ]
        for (name, accent), offset in zip(TOOL_STACK, offsets):
            chip = tool_chip(name, accent).move_to(sandbox_shell.get_center() + offset)
            tool_chips.append(chip)

        rich_card = self.build_rich_card().move_to(RIGHT * 4.95 + UP * 1.92)
        report_card = self.build_report_card().move_to(RIGHT * 4.96 + DOWN * 0.02)
        gate_card = self.build_gate_card().move_to(RIGHT * 4.95 + DOWN * 2.2)

        ingress_arrow = Arrow(
            terminal.get_right() + RIGHT * 0.05,
            sandbox_shell.get_left() + LEFT * 0.05,
            buff=0.12,
            stroke_width=5,
            max_tip_length_to_length_ratio=0.08,
            color=TEAL,
        )
        summary_arrow = Arrow(
            sandbox_shell.get_right() + RIGHT * 0.02 + UP * 0.78,
            rich_card.get_left() + LEFT * 0.12,
            buff=0.1,
            stroke_width=4,
            max_tip_length_to_length_ratio=0.09,
            color=BLUE,
        )
        report_arrow = Arrow(
            sandbox_shell.get_right() + RIGHT * 0.02,
            report_card.get_left() + LEFT * 0.12,
            buff=0.1,
            stroke_width=4,
            max_tip_length_to_length_ratio=0.09,
            color=TEAL,
        )
        install_arrow = Arrow(
            report_card.get_bottom() + DOWN * 0.06,
            gate_card.get_top() + UP * 0.08,
            buff=0.08,
            stroke_width=4,
            max_tip_length_to_length_ratio=0.09,
            color=GREEN,
        )

        return Layout(
            terminal=terminal,
            sandbox=sandbox,
            stage_card=stage_card,
            evidence_bus=evidence_bus,
            codex_core=codex_core,
            tool_chips=tool_chips,
            rich_card=rich_card,
            report_card=report_card,
            gate_card=gate_card,
            ingress_arrow=ingress_arrow,
            summary_arrow=summary_arrow,
            report_arrow=report_arrow,
            install_arrow=install_arrow,
        )

    def build_terminal_card(self) -> VGroup:
        shell = RoundedRectangle(
            width=4.15,
            height=2.15,
            corner_radius=0.28,
            fill_color=PANEL,
            fill_opacity=0.97,
            stroke_color=GREEN,
            stroke_width=2.2,
        )
        header = RoundedRectangle(
            width=4.15,
            height=0.38,
            corner_radius=0.28,
            fill_color=interpolate_color(PANEL, GREEN, 0.18),
            fill_opacity=1,
            stroke_width=0,
        ).align_to(shell, UP)
        dots = VGroup(*[
            Circle(radius=0.045, fill_color=color, fill_opacity=1, stroke_width=0)
            for color in ("#ff6a68", "#ffca57", "#2ed573")
        ]).arrange(RIGHT, buff=0.09).move_to(header.get_left() + RIGHT * 0.38)
        badge = brand_badge("pip-guard", "local CLI", shield_icon(color=GREEN), GREEN, width=2.08).scale(0.56)
        badge.next_to(shell.get_top(), DOWN, buff=0.44).align_to(shell, LEFT).shift(RIGHT * 0.22)
        prompt = label("$ pip-guard install <pkg>", 18, GREEN, BOLD)
        prompt.next_to(badge, DOWN, aligned_edge=LEFT, buff=0.26)
        caption = label("Rich progress + final verdict", 16, MUTED)
        caption.next_to(prompt, DOWN, aligned_edge=LEFT, buff=0.16)
        return VGroup(shell, header, dots, badge, prompt, caption)

    def build_stage_card(self) -> VGroup:
        card = RoundedRectangle(
            width=2.3,
            height=0.86,
            corner_radius=0.22,
            fill_color=interpolate_color(PANEL_ALT, TEAL, 0.08),
            fill_opacity=0.98,
            stroke_color=TEAL,
            stroke_width=2.0,
        )
        title = label("stage + resolve", 17, TEXT, BOLD).next_to(card.get_top(), DOWN, buff=0.13)
        files = VGroup(
            label("artifacts", 12, MUTED),
            label("uv.lock", 12, MUTED),
            label("pinned version", 12, MUTED),
        ).arrange(RIGHT, aligned_edge=UP, buff=0.18)
        files.next_to(title, DOWN, aligned_edge=LEFT, buff=0.12)
        files.align_to(card, LEFT).shift(RIGHT * 0.22)
        return VGroup(card, title, files)

    def build_evidence_bus(self) -> VGroup:
        bar = RoundedRectangle(
            width=4.02,
            height=0.22,
            corner_radius=0.11,
            fill_color=interpolate_color(PANEL_ALT, GOLD, 0.1),
            fill_opacity=0.98,
            stroke_color=GOLD,
            stroke_width=1.8,
        )
        title = label("evidence set", 11, MUTED, BOLD).next_to(bar, DOWN, buff=0.06)
        return VGroup(bar, title)

    def build_codex_core(self) -> VGroup:
        outer = Circle(radius=0.44, fill_color=interpolate_color(PANEL_ALT, GOLD, 0.12), fill_opacity=1, stroke_color=GOLD, stroke_width=2.8)
        middle = Circle(radius=0.27, fill_color=interpolate_color(PANEL, GOLD, 0.2), fill_opacity=1, stroke_color=GOLD, stroke_width=1.4)
        spark = spark_icon(0.18, GOLD).move_to(ORIGIN)
        title = label("Codex", 16, TEXT, BOLD).next_to(outer, DOWN, buff=0.08)
        subtitle = label("verdict engine", 11, MUTED).next_to(title, DOWN, buff=0.03)
        halo = Circle(radius=0.6, stroke_color=GOLD, stroke_width=5, stroke_opacity=0.12)
        return VGroup(halo, outer, middle, spark, title, subtitle)

    def build_rich_card(self) -> VGroup:
        card = soft_panel(3.12, 1.86, BLUE, "Rich progress", "local operator view")
        rows = fake_terminal_rows().move_to(card[1]).shift(DOWN * 0.28)
        return VGroup(card, rows)

    def build_report_card(self) -> VGroup:
        card = soft_panel(3.18, 2.2, TEAL, "HTML report", "shareable dossier")
        icon = doc_icon(0.34, TEAL).next_to(card[2], DOWN, buff=0.24).align_to(card[1], LEFT).shift(RIGHT * 0.42 + DOWN * 0.06)
        mini_table = fake_report_table().scale(0.62).move_to(card[1]).shift(RIGHT * 0.36 + DOWN * 0.14)
        footer = label("evidence + action", 11, MUTED).move_to(card[1]).shift(DOWN * 0.82)
        return VGroup(card, icon, mini_table, footer)

    def build_gate_card(self) -> VGroup:
        card = soft_panel(3.18, 1.7, GREEN, "install gate")
        pills = VGroup(
            self.pill("allow", GREEN),
            self.pill("warn", YELLOW),
            self.pill("block", RED),
        ).arrange(RIGHT, buff=0.18)
        pills.move_to(card[1]).shift(DOWN * 0.02)
        footer = label("warn prompts before install", 10, MUTED).move_to(card[1]).shift(DOWN * 0.62)
        return VGroup(card, pills, footer)

    def pill(self, text: str, accent: str) -> VGroup:
        shell = RoundedRectangle(width=0.88, height=0.34, corner_radius=0.17, fill_color=accent, fill_opacity=0.18, stroke_color=accent, stroke_width=1.7)
        text_obj = label(text, 14, accent, BOLD).move_to(shell)
        return VGroup(shell, text_obj)

    def make_stage_pulses(self, stage_card: VGroup, tool_chips: list[VGroup]) -> list[VMobject]:
        start = stage_card[0].get_bottom() + DOWN * 0.02
        arrows: list[VMobject] = []
        for chip in tool_chips:
            arrow = Arrow(
                start,
                chip.get_top() + UP * 0.02,
                buff=0.1,
                stroke_width=2.2,
                max_tip_length_to_length_ratio=0.07,
                color=interpolate_color(TEAL, WHITE, 0.12),
            )
            arrows.append(arrow)
        return arrows

    def make_codex_arrows(self, tool_chips: list[VGroup], evidence_bus: VGroup, codex_core: VGroup) -> list[VMobject]:
        bus_bar = evidence_bus[0]
        arrows: list[VMobject] = []
        for chip in tool_chips:
            arrow = Arrow(
                chip.get_bottom() + DOWN * 0.02,
                [chip.get_center()[0], bus_bar.get_top()[1], 0],
                color=interpolate_color(GOLD, WHITE, 0.1),
                stroke_width=2.1,
                buff=0.08,
                max_tip_length_to_length_ratio=0.08,
            )
            arrows.append(arrow)
        arrows.append(
            Arrow(
                bus_bar.get_bottom() + DOWN * 0.02,
                codex_core[1].get_top() + UP * 0.02,
                color=interpolate_color(GOLD, WHITE, 0.1),
                stroke_width=2.6,
                buff=0.08,
                max_tip_length_to_length_ratio=0.08,
            )
        )
        return arrows

    def make_cleanup_overlay(self, sandbox: VGroup) -> VGroup:
        shell = RoundedRectangle(
            width=2.7,
            height=0.9,
            corner_radius=0.24,
            fill_color=interpolate_color(PANEL_ALT, BLUE, 0.15),
            fill_opacity=0.98,
            stroke_color=BLUE,
            stroke_width=2.0,
        ).next_to(sandbox, DOWN, buff=0.42).align_to(sandbox, LEFT).shift(RIGHT * 0.8)
        moon = AnnularSector(inner_radius=0.08, outer_radius=0.24, angle=PI * 1.72, start_angle=PI / 2, fill_color=BLUE, fill_opacity=1, stroke_width=0)
        moon.move_to(shell.get_left() + RIGHT * 0.35)
        title = label("clear + idle", 17, TEXT, BOLD).move_to(shell).shift(LEFT * 0.02 + UP * 0.1)
        subtitle = label("scratch cleared", 12, MUTED).move_to(shell).shift(RIGHT * 0.08 + DOWN * 0.2)
        return VGroup(shell, moon, title, subtitle)


class PipGuardArchitecturePoster(PipGuardArchitectureAnimation):
    def construct(self) -> None:
        self.camera.background_color = BG
        self.add(self.build_backdrop())
        title = VGroup(
            label("pip-guard architecture", 44, TEXT, BOLD),
            label("Daytona sandbox review, Codex verdict, HTML report, gated install", 22, MUTED),
        ).arrange(DOWN, buff=0.14)
        title.to_edge(UP, buff=0.36)
        layout = self.build_layout()
        stage_pulse_arrows = self.make_stage_pulses(layout.stage_card, layout.tool_chips)
        tool_codex_arrows = self.make_codex_arrows(layout.tool_chips, layout.evidence_bus, layout.codex_core)
        cleanup = self.make_cleanup_overlay(layout.sandbox)
        self.add(
            title,
            layout.terminal,
            layout.sandbox,
            layout.stage_card,
            layout.evidence_bus,
            *stage_pulse_arrows,
            *layout.tool_chips,
            *tool_codex_arrows,
            layout.codex_core,
            layout.rich_card,
            layout.report_card,
            layout.gate_card,
            layout.ingress_arrow,
            layout.summary_arrow,
            layout.report_arrow,
            layout.install_arrow,
            cleanup,
        )
