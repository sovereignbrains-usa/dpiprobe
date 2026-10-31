package probe

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	// tcpInfoEvery is how often the debug probe reads the kernel counters.
	// 100 ms resolves the first retransmit (hundreds of ms) and adds no
	// packets of its own.
	tcpInfoEvery = 100 * time.Millisecond
	// tcpInfoFor is the same window the real probes wait out today, so the
	// trace covers the whole silence we might later cut short.
	tcpInfoFor = 8 * time.Second
)

// tcpWatchHost is the closed name from the task: TLS DROP on this ISP,
// while ya.ru (tlsRUControl) answers. One of each, in order, not a burst.
var tcpWatchHost = "www.instagram.com"

// tcpWatchFatID is one foreign address the 16 KB probe froze on
// (STALL around 24 KB in the 28.10 run). Looked up in the embedded list
// so the address lives in one place.
const tcpWatchFatID = "HE-01"

type tcpSample struct {
	At time.Duration
	TCPInfo
	Err error
}

// RunTCPInfoProbe prints a TCP-info trace for one closed name, one open
// name, and one 16 KB address. It does not change any verdict. local, when
// set, is the source address of those three sockets.
func RunTCPInfoProbe(ctx context.Context, w io.Writer) error {
	return runTCPInfoProbe(ctx, w, nil)
}

func runTCPInfoProbe(ctx context.Context, w io.Writer, local net.IP) error {
	if names := upVPNNames(); len(names) > 0 {
		fmt.Fprintf(w, "ВНИМАНИЕ: поднят VPN (%s).\n", strings.Join(names, ", "))
	}
	fmt.Fprintf(w, "интервал %s, окно %s\n", tcpInfoEvery, tcpInfoFor)
	p := New(tcpInfoFor, 1)
	for _, host := range []string{tcpWatchHost, tlsRUControl} {
		ips, err := p.LookupHost(ctx, host)
		if err != nil {
			fmt.Fprintf(w, "== %s: DNS: %s\n", host, err)
			continue
		}
		watchClientHello(ctx, w, host, ips[0].String(), local)
	}
	targets, err := DefaultTargets()
	if err != nil {
		return err
	}
	for _, t := range targets {
		if t.ID != tcpWatchFatID {
			continue
		}
		sni := t.SNI
		if sni == "" {
			sni = defaultSNI
		}
		watchFat(ctx, w, t, sni, local)
		return nil
	}
	return fmt.Errorf("tcpinfo: в списке нет %s", tcpWatchFatID)
}

func upVPNNames() []string {
	var names []string
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp != 0 && vpnIfaceRe.MatchString(ifc.Name) {
			names = append(names, ifc.Name)
		}
	}
	return names
}

func watchClientHello(ctx context.Context, w io.Writer, host, ip string, local net.IP) {
	tcp, err := dialTCPInfo(ctx, ip, 443, local)
	if err != nil {
		fmt.Fprintf(w, "== ClientHello %s → %s: соединение: %s\n", host, ip, err)
		return
	}
	defer tcp.Close()
	fmt.Fprintf(w, "\n== ClientHello %s → %s local %s ==\n", host, ip, tcp.LocalAddr())
	base, baseErr := ReadTCPInfo(tcp)
	if baseErr != nil {
		fmt.Fprintf(w, "снимок до записи: %s\n", baseErr)
	}
	_ = tcp.SetDeadline(time.Now().Add(tcpInfoFor))
	hsErr := make(chan error, 1)
	go func() {
		hsErr <- tls.Client(tcp, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true, //nolint:gosec // probe, the certificate is not the question
			NextProtos:         []string{"http/1.1"},
		}).HandshakeContext(ctx)
	}()
	samples := collectTCPInfo(ctx, tcp, tcpInfoFor)
	var hs error
	select {
	case hs = <-hsErr:
	case <-time.After(2 * time.Second):
		hs = fmt.Errorf("рукопожатие не вернулось")
	}
	writeTCPTable(w, samples)
	fmt.Fprintf(w, "рукопожатие: %s\n", hsText(hs))
	fmt.Fprintln(w, interpretHello(base, samples))
}

func watchFat(ctx context.Context, w io.Writer, t Target, sni string, local net.IP) {
	tcp, err := dialTCPInfo(ctx, t.IP, t.Port, local)
	if err != nil {
		fmt.Fprintf(w, "== 16 КБ %s %s: соединение: %s\n", t.ID, t.IP, err)
		return
	}
	defer tcp.Close()
	fmt.Fprintf(w, "\n== 16 КБ %s %s:%d sni %s local %s ==\n", t.ID, t.IP, t.Port, sni, tcp.LocalAddr())
	_ = tcp.SetDeadline(time.Now().Add(tcpInfoFor))
	tlsConn := tls.Client(tcp, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, //nolint:gosec // probe, the certificate is not the question
		NextProtos:         []string{"http/1.1"},
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		fmt.Fprintf(w, "рукопожатие не прошло: %s\n", err)
		samples := collectTCPInfo(ctx, tcp, tcpInfoFor)
		writeTCPTable(w, samples)
		fmt.Fprintln(w, interpretHello(TCPInfo{}, samples))
		return
	}
	base, baseErr := ReadTCPInfo(tcp)
	if baseErr != nil {
		fmt.Fprintf(w, "снимок после рукопожатия: %s\n", baseErr)
	} else {
		fmt.Fprintf(w, "после рукопожатия: RttUs %d BytesInFlight %d BytesRetrans %d TimeoutEpisodes %d BytesIn %d BytesOut %d ядро %d байт\n",
			base.RttUs, base.BytesInFlight, base.BytesRetrans, base.TimeoutEpisodes, base.BytesIn, base.BytesOut, base.RawBytes)
	}
	// A fresh window: the handshake consumed the previous deadline.
	_ = tcp.SetDeadline(time.Time{})
	_ = tcp.SetDeadline(time.Now().Add(tcpInfoFor))
	type fatDone struct {
		sent int
		err  error
	}
	done := make(chan fatDone, 1)
	go func() {
		n, err := pushFat(tlsConn, sni)
		done <- fatDone{n, err}
	}()
	samples := collectTCPInfo(ctx, tcp, tcpInfoFor)
	writeTCPTable(w, samples)
	var res fatDone
	select {
	case res = <-done:
	default:
		res.err = fmt.Errorf("запись ещё идёт")
	}
	fmt.Fprintf(w, "запись: %d байт, %s\n", res.sent, hsText(res.err))
	fmt.Fprintln(w, interpretFat(base, samples))
}

func pushFat(conn net.Conn, sni string) (int, error) {
	pad := make([]byte, fatChunk)
	if _, err := rand.Read(pad); err != nil {
		return 0, err
	}
	for i := range pad {
		pad[i] = 'a' + pad[i]%26
	}
	br := bufio.NewReader(conn)
	sent := 0
	for i := 0; sent < fatTotal && i < fatMaxReqs; i++ {
		var b bytes.Buffer
		fmt.Fprintf(&b, "HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\n", hostFor("", sni), userAgent)
		if i > 0 {
			b.WriteString("X-Pad: ")
			b.Write(pad)
			b.WriteString("\r\n")
		}
		b.WriteString("\r\n")
		n, err := conn.Write(b.Bytes())
		sent += n
		if err != nil {
			return sent, err
		}
		resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodHead})
		if err != nil {
			return sent, err
		}
		resp.Body.Close()
	}
	return sent, nil
}

func dialTCPInfo(ctx context.Context, ip string, port int, local net.IP) (*net.TCPConn, error) {
	var d net.Dialer
	d.Timeout = tcpInfoFor
	if local != nil {
		d.LocalAddr = &net.TCPAddr{IP: local}
	}
	c, err := d.DialContext(ctx, "tcp4", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	tcp := c.(*net.TCPConn)
	_ = tcp.SetNoDelay(true)
	return tcp, nil
}

func collectTCPInfo(ctx context.Context, tcp *net.TCPConn, dur time.Duration) []tcpSample {
	var out []tcpSample
	start := time.Now()
	tick := time.NewTicker(tcpInfoEvery)
	defer tick.Stop()
	end := time.NewTimer(dur)
	defer end.Stop()
	for {
		info, err := ReadTCPInfo(tcp)
		out = append(out, tcpSample{At: time.Since(start), TCPInfo: info, Err: err})
		if err != nil {
			return out
		}
		select {
		case <-ctx.Done():
			return out
		case <-end.C:
			return out
		case <-tick.C:
		}
	}
}

func writeTCPTable(w io.Writer, samples []tcpSample) {
	fmt.Fprintln(w, "мс\tRttUs\tBytesInFlight\tBytesRetrans\tTimeoutEpisodes\tBytesIn\tBytesOut")
	for _, s := range samples {
		if s.Err != nil {
			fmt.Fprintf(w, "%d\t%s\n", s.At.Milliseconds(), s.Err)
			continue
		}
		fmt.Fprintf(w, "%d\t%d\t%d\t%d\t%d\t%d\t%d\n",
			s.At.Milliseconds(), s.RttUs, s.BytesInFlight, s.BytesRetrans, s.TimeoutEpisodes, s.BytesIn, s.BytesOut)
	}
}

func hsText(err error) string {
	if err == nil {
		return "ok"
	}
	return err.Error()
}

// interpretHello reads a ClientHello trace. base is the snapshot from
// before the handshake wrote anything, so SYN-ACK payload is not mistaken
// for a ServerHello.
func interpretHello(base TCPInfo, samples []tcpSample) string {
	return interpretTCP(base, samples, false)
}

// interpretFat reads the upload that follows a finished handshake. base is
// the snapshot after the handshake, so the certificate is not counted as
// an answer to the fat requests.
func interpretFat(base TCPInfo, samples []tcpSample) string {
	return interpretTCP(base, samples, true)
}

func interpretTCP(base TCPInfo, samples []tcpSample, fat bool) string {
	var maxFlight, maxRetrans, maxTimeout uint32
	var maxIn, maxOut uint64
	var last TCPInfo
	var lastOK bool
	var firstRetrans, firstTimeout time.Duration
	var ioctlErr string
	var raw int
	for _, s := range samples {
		if s.Err != nil {
			ioctlErr = s.Err.Error()
			continue
		}
		last, lastOK = s.TCPInfo, true
		if raw == 0 {
			raw = s.RawBytes
		}
		if s.BytesInFlight > maxFlight {
			maxFlight = s.BytesInFlight
		}
		if s.BytesRetrans > maxRetrans {
			if maxRetrans == 0 {
				firstRetrans = s.At
			}
			maxRetrans = s.BytesRetrans
		}
		if s.TimeoutEpisodes > maxTimeout {
			if maxTimeout == 0 {
				firstTimeout = s.At
			}
			maxTimeout = s.TimeoutEpisodes
		}
		if s.BytesIn > maxIn {
			maxIn = s.BytesIn
		}
		if s.BytesOut > maxOut {
			maxOut = s.BytesOut
		}
	}
	if !lastOK {
		if ioctlErr != "" {
			return "итог: ioctl: " + ioctlErr
		}
		return "итог: нет снимков"
	}
	inGrew := maxIn > base.BytesIn
	sent := maxOut > base.BytesOut
	// flightZero is not required for a fast server: the ACK can land
	// between samples, so in-flight is already 0 on every row.
	kind := "смешанно"
	switch {
	case inGrew && last.BytesInFlight == 0:
		kind = "ответ пришёл"
	case sent && (maxRetrans > 0 || maxTimeout > 0) && last.BytesInFlight > 0 && !inGrew:
		kind = "не подтверждены"
	case sent && last.BytesInFlight == 0 && !inGrew && maxRetrans == 0 && maxTimeout == 0:
		kind = "подтверждены, ответа нет"
	case sent && last.BytesInFlight == 0 && !inGrew:
		kind = "повторы были, потом подтвердили, ответа нет"
	}
	if fat && inGrew && last.BytesInFlight > 0 && (maxRetrans > 0 || maxTimeout > 0) {
		// The first small response can raise BytesIn. What matters is
		// whether the later padding stayed unacknowledged.
		kind = "не подтверждены"
	}
	when := func(d time.Duration, happened bool) string {
		if !happened {
			return "—"
		}
		return fmt.Sprintf("%d мс", d.Milliseconds())
	}
	return fmt.Sprintf("итог: %s; rtt_us=%d max_inflight=%d end_inflight=%d retrans=%d (с %s) timeouts=%d (с %s) bytes_in %d→%d bytes_out %d→%d ядро %d байт",
		kind, last.RttUs, maxFlight, last.BytesInFlight, maxRetrans, when(firstRetrans, maxRetrans > 0),
		maxTimeout, when(firstTimeout, maxTimeout > 0), base.BytesIn, maxIn, base.BytesOut, maxOut, raw)
}
