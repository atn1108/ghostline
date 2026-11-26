import { beforeAll, beforeEach, expect, test, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { Vpn } from "./Vpn";
import { useGhost } from "../../../app/store";
import { initI18n } from "../../../i18n";

const svc = vi.hoisted(() => ({
  VPNInfo: vi.fn(),
  VPNAdd: vi.fn(() => Promise.resolve({ id: "b1", name: "jp" })),
  VPNDelete: vi.fn(() => Promise.resolve()),
  VPNConnect: vi.fn(() => Promise.resolve()),
  VPNDisconnect: vi.fn(() => Promise.resolve()),
  VPNSetBinary: vi.fn(() => Promise.resolve()),
  VPNDetectBinary: vi.fn(() => "/usr/sbin/openvpn"),
}));
vi.mock("../../../app/api", () => ({ Service: svc }));

const base = {
  supported: true,
  binary: "/usr/sbin/openvpn",
  detected: "/usr/sbin/openvpn",
  profiles: [] as any[],
  status: { phase: "idle", profileId: "", since: 0, error: "", log: [] as string[] },
};

const profile = {
  id: "p1",
  name: "vpngate",
  host: "219.100.37.104",
  port: 443,
  proto: "tcp",
  dev: "tun",
  remotes: 4,
  needsAuth: true,
  created: 0,
};

beforeAll(() => initI18n("vi"));
beforeEach(() => {
  vi.clearAllMocks();
  useGhost.getState().reset();
  useGhost.getState().setVPN(null);
  svc.VPNInfo.mockResolvedValue(structuredClone(base));
  // jsdom may not give File a text() method; the page reads the picked file
  // that way, so supply it when it is missing.
  if (typeof File.prototype.text !== "function") {
    Object.defineProperty(File.prototype, "text", {
      value: function (this: File) {
        return new Promise<string>((resolve) => {
          const r = new FileReader();
          r.onload = () => resolve(String(r.result));
          r.readAsText(this);
        });
      },
      configurable: true,
    });
  }
});

test("shows the openvpn path and an empty profile list", async () => {
  render(<Vpn />);
  expect(await screen.findByText("/usr/sbin/openvpn")).toBeInTheDocument();
  expect(screen.getByText(/chưa có hồ sơ/)).toBeInTheDocument();
  // The phase shows in the header and again in the tunnel panel.
  expect(screen.getAllByText("chưa kết nối").length).toBeGreaterThan(0);
});

test("a profile that asks for auth sends the credentials", async () => {
  svc.VPNInfo.mockResolvedValue({ ...structuredClone(base), profiles: [profile] });
  render(<Vpn />);
  fireEvent.change(await screen.findByLabelText("tên người dùng"), { target: { value: "vpn" } });
  fireEvent.change(screen.getByLabelText("mật khẩu"), { target: { value: "vpn" } });
  fireEvent.click(screen.getByRole("button", { name: "kết nối" }));
  await waitFor(() => expect(svc.VPNConnect).toHaveBeenCalledWith("p1", "vpn", "vpn"));
});

test("importing an .ovpn file hands its text to the backend", async () => {
  render(<Vpn />);
  const input = await screen.findByLabelText("nhập .ovpn");
  const file = new File(["remote 219.100.37.104 443\nproto tcp\n"], "jp.ovpn", { type: "text/plain" });
  fireEvent.change(input, { target: { files: [file] } });
  await waitFor(() =>
    expect(svc.VPNAdd).toHaveBeenCalledWith("jp.ovpn", expect.stringContaining("remote 219.100.37.104 443")),
  );
});

test("a profile that runs commands is refused and the message shows", async () => {
  svc.VPNAdd.mockRejectedValueOnce(new Error("VPN_UNSAFE: vpn: the profile runs commands: up"));
  render(<Vpn />);
  const input = await screen.findByLabelText("nhập .ovpn");
  fireEvent.change(input, { target: { files: [new File(["up /bin/sh"], "bad.ovpn")] } });
  expect(await screen.findByText(/Ghostline từ chối/)).toBeInTheDocument();
});

test("the tunnel panel offers a disconnect while the tunnel is up", async () => {
  svc.VPNInfo.mockResolvedValue({
    ...structuredClone(base),
    profiles: [profile],
    status: { phase: "connected", profileId: "p1", since: Date.now(), error: "", log: ["Initialization Sequence Completed"] },
  });
  render(<Vpn />);
  expect(await screen.findByText(/Initialization Sequence Completed/)).toBeInTheDocument();
  expect(screen.getAllByRole("button", { name: "ngắt" }).length).toBeGreaterThan(0);
  fireEvent.click(screen.getAllByRole("button", { name: "ngắt" })[0]);
  expect(svc.VPNDisconnect).toHaveBeenCalled();
});

test("delete requires confirmation and binary path can be saved or auto-detected", async () => {
  svc.VPNInfo.mockResolvedValue({ ...structuredClone(base), profiles: [profile] });
  render(<Vpn />);
  fireEvent.click(await screen.findByRole("button", { name: "xóa" }));
  expect(svc.VPNDelete).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "chắc chắn xóa?" }));
  await waitFor(() => expect(svc.VPNDelete).toHaveBeenCalledWith("p1"));

  const pathInput = screen.getByLabelText("đường dẫn openvpn");
  fireEvent.change(pathInput, { target: { value: "C:\\Program Files\\OpenVPN\\bin\\openvpn.exe" } });
  fireEvent.click(screen.getByRole("button", { name: "lưu" }));
  await waitFor(() => expect(svc.VPNSetBinary).toHaveBeenCalledWith("C:\\Program Files\\OpenVPN\\bin\\openvpn.exe"));

  fireEvent.click(screen.getByRole("button", { name: "tự dò" }));
  await waitFor(() => expect(svc.VPNSetBinary).toHaveBeenCalledWith(""));
});

test("live vpn:status events update the tunnel panel", async () => {
  svc.VPNInfo.mockResolvedValue({ ...structuredClone(base), profiles: [profile] });
  render(<Vpn />);
  await screen.findByText("vpngate");
  act(() => {
    useGhost.getState().setVPN({
      phase: "starting",
      profileId: "p1",
      since: 0,
      error: "",
      log: ["TCP connection established with [AF_INET]219.100.37.104:443"],
    });
  });
  expect(await screen.findByText(/TCP connection established/)).toBeInTheDocument();
  expect(screen.getAllByText(/đang kết nối…/).length).toBeGreaterThan(0);
});

test("dropping or pasting an .ovpn config imports it", async () => {
  const { container } = render(<Vpn />);
  const dropTarget = await screen.findByRole("button", { name: "thả file .ovpn vào đây" });
  const file = new File(["remote 219.100.37.104 443\nproto tcp\n"], "drop.ovpn", { type: "text/plain" });
  fireEvent.drop(dropTarget, { dataTransfer: { files: [file] } });
  await waitFor(() => expect(svc.VPNAdd).toHaveBeenCalledWith("drop.ovpn", expect.stringContaining("219.100.37.104")));

  fireEvent.paste(container.firstElementChild!, {
    clipboardData: { files: [], getData: () => "dev tun\nremote 1.2.3.4 443\n" },
  });
  await waitFor(() => expect(svc.VPNAdd).toHaveBeenCalledWith("pasted.ovpn", expect.stringContaining("1.2.3.4")));
});
