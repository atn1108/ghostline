import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Events, Window } from "@wailsio/runtime";
import { APP_LABEL } from "../../brand";
import type { Mode } from "../../app/store";
import type { Lang } from "../../i18n";
import css from "./TitleBar.module.css";

type Props = {
  mode: Mode;
  onMode: (m: Mode) => void | Promise<void>;
  lang: Lang;
  onLang: (l: Lang) => void;
};

const noDrag = { "--wails-draggable": "no-drag" } as React.CSSProperties;

export function TitleBar({ mode, onMode, lang, onLang }: Props) {
  const { t } = useTranslation();
  const other: Lang = lang === "vi" ? "en" : "vi";
  const [maximised, setMaximised] = useState(false);

  useEffect(() => {
    const sync = () => {
      if (typeof Window.IsMaximised === "function") {
        void Window.IsMaximised().then((v) => setMaximised(!!v), () => {});
      }
    };
    sync();
    const offs = typeof Events?.On === "function"
      ? [
          Events.On("common:WindowMaximise", () => setMaximised(true)),
          Events.On("common:WindowUnMaximise", () => setMaximised(false)),
          Events.On("common:WindowRestore", sync),
        ]
      : [];
    window.addEventListener("resize", sync);
    return () => {
      offs.forEach((off) => off?.());
      window.removeEventListener("resize", sync);
    };
  }, []);

  const onMaximise = async () => {
    if (mode === "simple") {
      await onMode("full");
      if (typeof Window.Maximise === "function") {
        await Window.Maximise();
      } else {
        await Window.ToggleMaximise?.();
      }
      setMaximised(true);
      return;
    }
    await Window.ToggleMaximise?.();
    if (typeof Window.IsMaximised === "function") {
      setMaximised(!!(await Window.IsMaximised()));
    } else {
      setMaximised((m) => !m);
    }
  };

  return (
    <header className={css.bar}>
      <div
        className={css.top}
        data-drag
        style={{ "--wails-draggable": "drag" } as React.CSSProperties}
        onDoubleClick={(e) => {
          if ((e.target as HTMLElement | null)?.closest("button")) return;
          void onMaximise();
        }}
      >
        <span className={css.label}>{APP_LABEL}</span>
        <div className={css.controls}>
          <button style={noDrag} className={css.lang} aria-label={`${t("title.language")}: ${other.toUpperCase()}`} onClick={() => onLang(other)}>
            {lang.toUpperCase()}/{other.toUpperCase()}
          </button>
          <button style={noDrag} aria-label={t("title.minimise")} onClick={() => void Window.Minimise()}>
            —
          </button>
          <button
            style={noDrag}
            aria-label={maximised ? t("title.restore") : t("title.maximise")}
            onClick={() => void onMaximise()}
          >
            {maximised ? "❐" : "□"}
          </button>
          <button style={noDrag} aria-label={t("title.close")} onClick={() => void Window.Close()}>
            ✕
          </button>
        </div>
      </div>
      <div className={css.tabs} role="tablist">
        {(["simple", "full"] as Mode[]).map((m) => (
          <button
            key={m}
            role="tab"
            aria-selected={mode === m}
            className={mode === m ? css.on : undefined}
            onClick={() => onMode(m)}
          >
            {mode === m ? `[${t(`mode.${m}`)}]` : t(`mode.${m}`)}
          </button>
        ))}
      </div>
    </header>
  );
}
