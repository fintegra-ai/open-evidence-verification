# Faz D — İlk Dilim: TypeScript Doğrulayıcı (Yürütme Planı)

Status: plan adopted 2026-11-01 (Faz D kickoff; implementation follows in the
next working session). Derived from the NLnet plan v2 §D and the
B+ normative drafts. Decision authority: project owner delegation, 2026-11-01.

## Amaç (Kapı D tanımı, hatırlatma)

Python referansı ile TypeScript doğrulayıcı **aynı vektör setinde %100 aynı
sonucu** verir; belirsizlik günlüğü (spec boşlukları) tutulur; tarayıcı
doğrulayıcı aynı kod tabanından çıkar. Kapı D'nin ölçütü budur — %100
parity sağlanmadan "conformant" iddiası yapılamaz (GOVERNANCE §3).

## Dilim 1 — kapsam (tek oturumda bitirilebilir, somut kabul ölçütüyle)

1. **Yeni depo** (karar: `open-evidence-verifier-ts`, `fintegra-ai` org'unda;
   oluşturulması owner aksiyonu). İsim kararını da owner verir — npm adı bu
   depo üzerinden yayınlanır (Faz D+ sürüm disiplini: PyPI ile aynı majör/minör
   çizgisi).
2. **ZIP okuyucu (stdlib-only)**: Node `node:zlib.inflateRawSync` ile
   central-directory parser (~100 satır). Local-header'a güvenilmez; EOCD'den
   okunur. Önce OEPT-1.0 §5 sırasının 1–2 adımı.
3. **JCS (RFC 8785)**: ES6 `JSON.stringify` sayı biçimi JCS'in referans
   davranışıdır; anahtar sıralaması recursive uygulanır; I-JSON kısıtı (tek
   başına surrogate yok, |int| ≤ 2^53−1) fail-closed. [spec: OEPT-1.0 §3]
4. **Ed25519 doğrulama**: `node:crypto` (sign/verify, 'ed25519') — canonical
   manifest bytes üzerinde. [spec: OEPT-1.0 §5(10), §7]
5. **Vektör sözleşmesi**: `run_vectors.py`'ın dış doğrulayıcı protokolünü
   uygular — `action: "verify"` için `{"vector_id", "exit_code", "result":
   {overall_result, checks}}` üretir. Desteklenmeyen action'lar için
   `{"exit_code": null, "result": {}, "unsupported": true}` döner (sessiz
   başarı YOK).
6. **Kabul ölçütü (dilim 1)**: OEVP runner `--verifier "node dist/cli.js {input}"`
   ile vektörler 01, 02, 03, 06 (verify action) **aynı sonuçla** geçer; diğer
   8 aktif vektör `unsupported` olarak raporlanır (fail-closed).

## Dilim 2+ (sıra)

- Manifest şema doğrulama (JSON Schema → TS derleme zamanı tip üretimi +
  çalışma zamanı katı doğrulama).
- Kalan action'lar (inspect-receipt, reverify) → parity hedefi 12/12.
- Tarayıcı hedefi: aynı çekirdek modüller, dosya girdisi yerine
  drag-and-drop ArrayBuffer; sunucuya veri gitmez.
- Belirsizlik günlüğü: her spec boşluğu `docs/ambiguity-log.md`'ye; spec
  düzeltmesi B sürecinden geçer.

## Bilinçli olmayanlar (dilim 1)

- ZIP yazma/bundle üretimi (yalnız okuma), stream arayüzleri, WASM, Rust/Go
  (plan D+: sonraki sıra), npm yayını (ilk parity raporundan önce değil).

## Kabul ritüeli

Her dilim bitiminde: OEVP vektör seti koşusu (runner raporu), Python/TS
çıktı farkının boş olması, ambiguity-log güncel — üçü METRICS.md'e işlenir.
