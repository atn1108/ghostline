import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Service, type VPNInfo, type VPNProfile } from "../../../app/api";
import { useGhost } from "../../../app/store";
import { describeError } from "../../../i18n";
import { Chip } from "../../../components/neon/Chip";
import { TerminalPanel, type Tone } from "../../../components/neon/TerminalPanel";
import css from "../full.module.css";

const phaseTone: Record<string, Tone> = { connected: "ok", starting: "warn", error: "err", idle: "dim" };
const phaseClass: Record<string, string> = { connected: "ok", starting: "warn", error: "bad", idle: "dim" };

type Creds = { user: string; pass: string };

// The VPN page: the OpenVPN engine on this machine, the imported profiles
// and the tunnel with openvpn's own log.
export function Vpn() {
  const { t } = useTranslation();
  const vpn = useGhost((s) => s.vpn);
  const [info, setInfo] = useState<VPNInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [path, setPath] = useState("");
  const [creds, setCreds] = useState<Record<string, Creds>>({});
  const [confirming, setConfirming] = useState("");
  const [dragging, setDragging] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const logRef = useRef<HTMLDivElement>(null);

  const reload = () => {
    Service.VPNInfo()
      .then((i) => {
        if (!i) return;
        setInfo(i);
        setPath((p) => p || i.binary || "");
      })
      .catch((e) => setError(describeError(e)));
  };
  useEffect(reload, []);
  // The list only changes here; the state comes from vpn:status events.
  useEffect(() => {
    if (vpn && info) setInfo({ ...info, status: vpn });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [vpn]);
  useEffect(() => {
    const el = logRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [info?.status.log?.length]);

  const run = (p: Promise<unknown>) =>
    p
      .then(() => {
        setError(null);
        reload();
      })
      .catch((e) => setError(describeError(e)));

  const addText = async (name: string, text: string) => {
    try {
      await Service.VPNAdd(name, text);
      setError(null);
      reload();
    } catch (e) {
      setError(describeError(e));
    }
  };

  const addFile = async (file: File) => addText(file.name, await file.text());

  const connect = (p: VPNProfile) => {
    const c = creds[p.id] ?? { user: "", pass: "" };
    run(Service.VPNConnect(p.id, c.user, c.pass));
  };

  if (!info) return null;
  const st = info.status;
  const profiles = info.profiles ?? [];
  const running = st.phase === "connected" || st.phase === "starting";
  const current = profiles.find((p) => p.id === st.profileId);

  return (
    <div
      className={css.page}
      data-file-drop-target=""
      onDragOver={(e) => {
        e.preventDefault();
        setDragging(true);
      }}
      onDragLeave={(e) => {
        if (!e.currentTarget.contains(e.relatedTarget as Node)) setDragging(false);
      }}
      onDrop={(e) => {
        e.preventDefault();
        setDragging(false);
        const f = e.dataTransfer?.files?.[0];
        if (f) void addFile(f);
      }}
      onPaste={(e) => {
        const tag = (e.target as HTMLElement | null)?.tagName;
        if (tag === "INPUT" || tag === "TEXTAREA") return;
        const f = e.clipboardData?.files?.[0];
        if (f) {
          e.preventDefault();
          void addFile(f);
          return;
        }
        const text = e.clipboardData?.getData("text");
        if (text && /^\s*(remote|client|dev)\b/m.test(text)) {
          e.preventDefault();
          void addText("pasted.ovpn", text);
        }
      }}
    >
      <div className={css.head}>
        <span>{t("vpn.title")}</span>
        <span className={`${css.count} ${css[phaseClass[st.phase] ?? "dim"]}`}>{t(`vpn.phase.${st.phase}`)}</span>
      </div>

      {error && <div className={css.bad}>✕ {error}</div>}
      {!info.supported && <div className={css.dim}>{t("errors.VPN_UNSUPPORTED.message")}</div>}

      {info.supported && (
        <>
          <div className={css.panel}>
        <div className={css.panelTitle}>{t("vpn.engine")}</div>
        {info.binary ? (
          <code className={css.code}>{info.binary}</code>
        ) : (
          <>
            <div className={css.bad}>✕ {t("vpn.engineMissing")}</div>
            <div className={css.dim}>{t("vpn.install")}</div>
          </>
        )}
        <div className={css.row} style={{ marginTop: 8 }}>
          <input
            aria-label={t("vpn.path")}
            placeholder={t("vpn.path")}
            style={{ flex: 1, minWidth: 180 }}
            value={path}
            onChange={(e) => setPath(e.target.value)}
          />
          <Chip onClick={() => run(Service.VPNSetBinary(path))}>{t("common.save")}</Chip>
          <Chip
            onClick={() => {
              setPath("");
              run(Service.VPNSetBinary(""));
            }}
          >
            {t("vpn.auto")}
          </Chip>
        </div>
      </div>

      <div className={css.panel}>
        <div className={css.panelTitle}>
          <span>{t("vpn.profiles")}</span>
          <span className={css.count}>{profiles.length}</span>
        </div>
        {profiles.length === 0 && <div className={css.dim}>{t("vpn.empty")}</div>}
        {profiles.map((p) => {
          const on = running && st.profileId === p.id;
          const c = creds[p.id] ?? { user: "", pass: "" };
          const setC = (patch: Partial<Creds>) => setCreds((m) => ({ ...m, [p.id]: { ...c, ...patch } }));
          return (
            <div key={p.id} className={css.vpnRow}>
              <div style={{ minWidth: 0 }}>
                <div className={css.vpnName}>
                  {p.name}
                  {on && <span className={st.phase === "connected" ? css.ok : css.warn}> · {t(`vpn.phase.${st.phase}`)}</span>}
                </div>
                <div className={css.vpnMeta}>
                  {p.host}:{p.port} · {p.proto}
                  {p.remotes > 1 ? ` · ${t("vpn.remotes", { n: p.remotes })}` : ""}
                  {p.needsAuth ? ` · ${t("vpn.needsAuth")}` : ""}
                </div>
                {p.needsAuth && !on && (
                  <div className={css.row} style={{ marginTop: 6 }}>
                    <input
                      aria-label={t("vpn.authUser")}
                      placeholder={t("vpn.authUser")}
                      value={c.user}
                      onChange={(e) => setC({ user: e.target.value })}
                    />
                    <input
                      type="password"
                      aria-label={t("vpn.authPass")}
                      placeholder={t("vpn.authPass")}
                      value={c.pass}
                      onChange={(e) => setC({ pass: e.target.value })}
                    />
                  </div>
                )}
              </div>
              <div className={css.row} style={{ gap: 6, flexShrink: 0 }}>
                <Chip active={on} disabled={running && !on} onClick={() => (on ? run(Service.VPNDisconnect()) : connect(p))}>
                  {on ? t("vpn.disconnect") : t("vpn.connect")}
                </Chip>
                {confirming === p.id ? (
                  <Chip
                    onClick={() => {
                      setConfirming("");
                      void run(Service.VPNDelete(p.id));
                    }}
                  >
                    {t("vpn.deleteConfirm")}
                  </Chip>
                ) : (
                  <Chip onClick={() => setConfirming(p.id)}>{t("vpn.delete")}</Chip>
                )}
              </div>
            </div>
          );
        })}
        <div className={css.row} style={{ marginTop: 10 }}>
          <Chip onClick={() => fileRef.current?.click()}>{t("vpn.import")}</Chip>
          <span className={css.dim}>{t("vpn.dropHint")}</span>
        </div>
        <input
          ref={fileRef}
          type="file"
          hidden
          aria-label={t("vpn.import")}
          accept=".ovpn,.conf,text/plain"
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) void addFile(f);
            e.target.value = "";
          }}
        />
        <button
          type="button"
          data-file-drop-target=""
          className={`${css.vpnDrop} ${dragging ? css.vpnDropActive : ""}`}
          onClick={() => fileRef.current?.click()}
        >
          {t("vpn.dropZone")}
        </button>
      </div>

      <div className={css.panel}>
        <div className={css.panelTitle}>
          <span>{t("vpn.tunnel")}</span>
          {st.phase === "connected" && st.since > 0 && (
            <span className={css.count}>{t("vpn.since", { time: new Date(st.since).toLocaleTimeString() })}</span>
          )}
        </div>
        <div className={css.log} style={{ maxHeight: 260, minHeight: 120 }} ref={logRef}>
          <TerminalPanel
            rows={[
              { k: t("vpn.tunnel"), v: t(`vpn.phase.${st.phase}`), tone: phaseTone[st.phase] ?? "dim" },
              { k: t("vpn.profile"), v: current?.name ?? "—" },
              ...(st.error ? [{ k: t("vpn.error"), v: st.error, tone: "err" as Tone }] : []),
            ]}
            lines={st.log ?? []}
          />
        </div>
        {st.phase === "connected" && <div className={css.warn}>⚠ {t("vpn.hint")}</div>}
          <div className={css.row} style={{ marginTop: 8 }}>
            {running ? (
              <Chip onClick={() => run(Service.VPNDisconnect())}>{t("vpn.disconnect")}</Chip>
            ) : (
              <Chip onClick={reload}>{t("common.retry")}</Chip>
            )}
          </div>
        </div>
        </>
      )}
    </div>
  );
}
