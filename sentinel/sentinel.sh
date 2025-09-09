#!/usr/bin/env bash
# sentinel.sh
# AI-style log anomaly detection using an n-gram (unigram + bigram) language model.
# Pure Bash + awk + coreutils. No internet needed.
#
# Modes:
#   train  : Learn a baseline model from "normal" logs
#   score  : Score a file, emit anomalies and an HTML report
#   watch  : Tail logs in near-real-time, print high-scoring anomalies
#   explain: Explain why a specific line scored as anomalous
#
# Example quickstart:
#   ./sentinel.sh train  --model ./model --input /var/log/syslog
#   ./sentinel.sh score  --model ./model --input /var/log/syslog --out ./report.html
#   ./sentinel.sh watch  --model ./model --input /var/log/auth.log
#   echo "suspicious ssh root@1.2.3.4" | ./sentinel.sh explain --model ./model
#
set -euo pipefail

VERSION="1.0.0"
PROG="${0##*/}"
RED=$'\033[31m'; GRN=$'\033[32m'; YLW=$'\033[33m'; BLU=$'\033[34m'; DIM=$'\033[2m'; RST=$'\033[0m'

usage() {
  cat <<EOF
${PROG} v${VERSION} — AI-style log anomaly detector (Bash + awk)

USAGE:
  ${PROG} train  --model DIR --input FILE [--min-count N]
  ${PROG} score  --model DIR --input FILE [--out REPORT.html] [--threshold Z] [--top K]
  ${PROG} watch  --model DIR --input FILE [--threshold Z]
  ${PROG} explain --model DIR [--line "text to explain"]

OPTIONS:
  --model DIR        Directory to store/read model files.
  --input FILE       Log file to learn from or score.
  --min-count N      Ignore tokens seen < N times during training (default: 1).
  --threshold Z      Anomaly Z-score threshold (default: 2.5).
  --top K            Limit to top-K anomalies in report (default: 200).
  --out FILE         Emit an HTML report (score mode only).
  --line STR         A single line to explain (explain mode).
  -h, --help         Show this help.

NOTES:
  • Tokenization is simple, whitespace + punctuation boundaries. Lowercased.
  • Model = unigram.tsv, bigram.tsv, stats.tsv (stored in --model DIR).
  • Scoring uses negative log-likelihood with add-1 smoothing + robust Z-scores.
  • "watch" uses tail -F to stream anomalies as they happen.

EOF
}

die() { echo "${RED}error:${RST} $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing dependency: $1"; }

# Dependencies (standard on most systems)
for bin in awk sed tr sort uniq paste cut tail head tee date; do need "$bin"; done

# --------------- AWK LIB: shared n-gram logic -----------------
AWK_TOKENIZE='
function tokdown(s) { gsub(/[^[:alnum:]_]+/, " ", s); return tolower(s) }
function split_tokens(s, arr,    n) {
  s = tokdown(s)
  n = split(s, arr, /[[:space:]]+/)
  return n
}
'

# Training: produce unigram & bigram counts
AWK_TRAIN="
${AWK_TOKENIZE}
{
  n = split_tokens(\$0, t)
  for (i=1; i<=n; i++) {
    if (t[i] != \"\") unigrams[t[i]]++
    if (i<n && t[i] != \"\" && t[i+1] != \"\") bigrams[t[i] SUBSEP t[i+1]]++
  }
}
END{
  # unigrams
  for (u in unigrams) printf(\"%s\t%d\n\", u, unigrams[u]) > U
  # bigrams
  for (b in bigrams) { split(b, xy, SUBSEP); printf(\"%s\t%s\t%d\n\", xy[1], xy[2], bigrams[b]) > B }
}
"

# Scoring: compute per-line negative log-likelihood with add-1 smoothing.
# Also compute token & bigram contributions for explainability.
AWK_SCORE="
${AWK_TOKENIZE}
BEGIN{
  FS=\"\\t\"
  while ((getline < UFILE) > 0) { uni[\$1]=\$2; total_uni+=\$2 }
  while ((getline < BFILE) > 0) { bi[\$1 SUBSEP \$2]=\$3; }
  # build continuation counts per-left-token for smoothing
  for (k in bi) { split(k,xy,SUBSEP); left=xy[1]; left_total[left]+=bi[k] }
  # robust stats
  P25=META[\"p25\"]; P50=META[\"p50\"]; P75=META[\"p75\"]; MAD=META[\"mad\"]; if (MAD==0) MAD=1
}
function rob_z(x, m, mad,    z){ z = 0.6745*(x - m)/mad; return z }
function nll_line(arr, n,    i, u, v, p_u, p_v_u, nll, contrib, key, msg) {
  nll=0; contrib=\"\"
  for (i=1; i<=n; i++) {
    u=arr[i]; if (u==\"\") continue
    p_u=( (uni[u]+1) / (total_uni + vocab) )
    nll+= -log(p_u)
    if (i<n && arr[i+1]!=\"\") {
      v=arr[i+1]
      key=u SUBSEP v
      p_v_u = ( (bi[key]+1) / (left_total[u] + vocab) )
      nll+= -log(p_v_u)
      contrib = contrib sprintf(\"%s→%s:%.4f \", u, v, -log(p_v_u))
    } else {
      contrib = contrib sprintf(\"%s:%.4f \", u, -log(p_u))
    }
  }
  return nll
}
{
  raw=\$0; n=split_tokens(raw, t)
  vocab=length(uni)  # shared for smoothing
  score = nll_line(t, n)
  z = rob_z(score, P50, MAD)
  printf(\"%f\\t%f\\t%s\\n\", score, z, raw)
}
"

# --------------- Helpers -----------------
abs() { awk -v x="${1}" 'BEGIN{print (x<0)?-x:x}'; }
timestamp() { date +"%Y-%m-%d %H:%M:%S"; }

ensure_model_dir() {
  local d="$1"
  [[ -d "$d" ]] || mkdir -p "$d"
}

write_model_stats() {
  local model="$1" stats="$2"
  printf "%s\n" "$stats" > "${model}/stats.tsv"
}

read_model_stat() {
  local model="$1" key="$2"
  awk -F'\t' -v k="$key" '$1==k{print $2}' "${model}/stats.tsv" 2>/dev/null || true
}

compute_robust_stats() {
  # Reads a file with first column = score; outputs P25, P50, P75, MAD
  awk '
  { s[NR]=$1 } END{
    if (NR==0){print "p25\t0\np50\t0\np75\t0\nmad\t1"; exit}
    n=asort(s)
    q25 = s[int(0.25*n) ? int(0.25*n) : 1]
    q50 = s[int(0.50*n) ? int(0.50*n) : 1]
    q75 = s[int(0.75*n) ? int(0.75*n) : 1]
    # MAD: median(|x - median|)
    for (i=1;i<=n;i++){ d[i]= (s[i]>q50 ? s[i]-q50 : q50-s[i]) }
    m=asort(d)
    mad = d[int(0.50*m) ? int(0.50*m) : 1]
    printf("p25\t%f\np50\t%f\np75\t%f\nmad\t%f\n", q25,q50,q75,(mad==0?1:mad))
  }'
}

html_report() {
  # $1 = anomalies.tsv (score \t z \t line), $2=outfile, $3=model stats, $4=input file
  local anomalies="$1" out="$2" stats="$3" src="$4"
  local p25 p50 p75 mad
  p25=$(echo "$stats" | awk '$1=="p25"{print $2}')
  p50=$(echo "$stats" | awk '$1=="p50"{print $2}')
  p75=$(echo "$stats" | awk '$1=="p75"{print $2}')
  mad=$(echo "$stats" | awk '$1=="mad"{print $2}')
  cat > "$out" <<EOF
<!doctype html>
<html><head><meta charset="utf-8"><title>Sentinel Report</title>
<style>
 body{font-family:ui-sans-serif,system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:24px}
 h1{margin:0 0 8px} .dim{color:#666} code{background:#f6f8fa;padding:2px 4px;border-radius:4px}
 table{border-collapse:collapse;width:100%;margin-top:16px}
 th,td{border-bottom:1px solid #eee;padding:8px;text-align:left;font-size:14px}
 .sev1{background:#fff} .sev2{background:#fff7e6} .sev3{background:#ffe9e9}
 .pill{display:inline-block;padding:2px 8px;border-radius:999px;background:#eee;font-size:12px}
</style></head><body>
<h1>Sentinel Anomaly Report</h1>
<p class="dim">Source: <code>${src}</code> • Generated: $(timestamp) • Model: unigram+bigram • Robust center: ${p50} (MAD ${mad})</p>
<table><thead><tr><th>#</th><th>Score</th><th>Z</th><th>Line</th></tr></thead><tbody>
EOF
  nl -ba "$anomalies" | awk -F'\t' '
    BEGIN{OFS="\t"}
    {
      idx=$1; score=$2; z=$3; line=""
      # Reconstruct original line (columns after 3rd)
      for (i=4;i<=NF;i++){ line=line $i ((i<NF)?"\t":"") }
      sev="sev1"; if (z>=3.5) sev="sev3"; else if (z>=2.5) sev="sev2";
      gsub(/&/,"&amp;",line); gsub(/</,"&lt;",line); gsub(/>/,"&gt;",line);
      printf("<tr class=\"%s\"><td>%s</td><td>%.4f</td><td><span class=\"pill\">%.2f</span></td><td><code>%s</code></td></tr>\n", sev, idx, score, z, line)
    }' >> "$out"
  echo "</tbody></table></body></html>" >> "$out"
}

# --------------- Commands -----------------

cmd_train() {
  local model="" input="" min_count="1"
  while [[ $# -gt 0 ]]; do case "$1" in
    --model) model="$2"; shift 2;;
    --input) input="$2"; shift 2;;
    --min-count) min_count="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) die "unknown arg: $1";;
  esac; done

  [[ -n "${model}" ]] || die "--model required"
  [[ -n "${input}" ]] || die "--input required"
  [[ -f "${input}" ]] || die "input not found: ${input}"
  ensure_model_dir "${model}"

  echo "${BLU}[*]${RST} Training model from ${input}"
  awk -v U="${model}/unigram.tsv" -v B="${model}/bigram.tsv" "${AWK_TRAIN}" "${input}"

  # Prune rare tokens if requested
  if [[ "${min_count}" -gt 1 ]]; then
    awk -v m="${min_count}" '$2>=m' "${model}/unigram.tsv" > "${model}/unigram.tsv.tmp" && mv "${model}/unigram.tsv.tmp" "${model}/unigram.tsv"
    awk -v m="${min_count}" 'NR==FNR{keep[$1]=1;next} ( ($1 in keep) && ($2 in keep) )' \
      "${model}/unigram.tsv" "${model}/bigram.tsv" > "${model}/bigram.tsv.tmp" && mv "${model}/bigram.tsv.tmp" "${model}/bigram.tsv"
  fi

  # Build bootstrap scores on training data to compute robust stats
  local tmp_scores
  tmp_scores="$(mktemp)"
  awk -v UFILE="${model}/unigram.tsv" -v BFILE="${model}/bigram.tsv" -v META["p25"]=0 -v META["p50"]=0 -v META["p75"]=0 -v META["mad"]=1 "${AWK_SCORE}" "${input}" > "${tmp_scores}"

  stats="$(compute_robust_stats < "${tmp_scores}")"
  write_model_stats "${model}" "${stats}"
  rm -f "${tmp_scores}"

  echo "${GRN}[+]${RST} Training complete. Model stored in ${model}"
}

cmd_score() {
  local model="" input="" out="" threshold="2.5" top="200"
  while [[ $# -gt 0 ]]; do case "$1" in
    --model) model="$2"; shift 2;;
    --input) input="$2"; shift 2;;
    --out) out="$2"; shift 2;;
    --threshold) threshold="$2"; shift 2;;
    --top) top="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) die "unknown arg: $1";;
  esac; done

  [[ -n "${model}" && -d "${model}" ]] || die "--model DIR missing/invalid"
  [[ -f "${model}/unigram.tsv" && -f "${model}/bigram.tsv" && -f "${model}/stats.tsv" ]] || die "model incomplete in ${model}"
  [[ -n "${input}" && -f "${input}" ]] || die "--input FILE missing/invalid"

  local p25 p50 p75 mad
  p25="$(read_model_stat "${model}" p25)"; p50="$(read_model_stat "${model}" p50)"
  p75="$(read_model_stat "${model}" p75)"; mad="$(read_model_stat "${model}" mad)"

  echo "${BLU}[*]${RST} Scoring ${input} (Z-threshold ${threshold})"
  local tmp_all tmp_top
  tmp_all="$(mktemp)"; tmp_top="$(mktemp)"

  awk -v UFILE="${model}/unigram.tsv" -v BFILE="${model}/bigram.tsv" \
      -v META["p25"]="${p25}" -v META["p50"]="${p50}" -v META["p75"]="${p75}" -v META["mad"]="${mad}" \
      "${AWK_SCORE}" "${input}" | sort -k2,2nr > "${tmp_all}"

  awk -v z="${threshold}" '$2>=z' "${tmp_all}" | head -n "${top}" > "${tmp_top}"

  echo "${GRN}[+]${RST} Found $(wc -l < "${tmp_top}") anomalies (z >= ${threshold})"
  if [[ -n "${out}" ]]; then
    html_report "${tmp_top}" "${out}" "$(cat "${model}/stats.tsv")" "${input}"
    echo "${GRN}[+]${RST} Report written: ${out}"
  else
    # pretty print to stdout
    nl -ba "${tmp_top}" | awk -F'\t' -v y="${YLW}" -v r="${RST}" '{printf("%s#%03d%s z=%.2f  %s\n", y, $1, r, $3, $4)}'
  fi

  rm -f "${tmp_all}" "${tmp_top}"
}

cmd_watch() {
  local model="" input="" threshold="2.5"
  while [[ $# -gt 0 ]]; do case "$1" in
    --model) model="$2"; shift 2;;
    --input) input="$2"; shift 2;;
    --threshold) threshold="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) die "unknown arg: $1";;
  esac; done

  [[ -n "${model}" && -d "${model}" ]] || die "--model DIR missing/invalid"
  [[ -f "${model}/unigram.tsv" && -f "${model}/bigram.tsv" && -f "${model}/stats.tsv" ]] || die "model incomplete in ${model}"
  [[ -n "${input}" && -f "${input}" ]] || die "--input FILE missing/invalid"

  local p25 p50 p75 mad
  p25="$(read_model_stat "${model}" p25)"; p50="$(read_model_stat "${model}" p50)"
  p75="$(read_model_stat "${model}" p75)"; mad="$(read_model_stat "${model}" mad)"

  echo "${BLU}[*]${RST} Watching ${input} (z >= ${threshold}). Ctrl-C to exit."
  tail -F "${input}" | awk -v UFILE="${model}/unigram.tsv" -v BFILE="${model}/bigram.tsv" \
      -v META["p25"]="${p25}" -v META["p50"]="${p50}" -v META["p75"]="${p75}" -v META["mad"]="${mad}" \
      "${AWK_SCORE}" | awk -v thr="${threshold}" -v y="${YLW}" -v r="${RST}" '
        $2>=thr { printf("%s%s%s z=%.2f | %s\n", y, strftime("%Y-%m-%d %H:%M:%S"), r, $2, substr($3,1,400)) ; fflush() }'
}

cmd_explain() {
  local model="" line=""
  while [[ $# -gt 0 ]]; do case "$1" in
    --model) model="$2"; shift 2;;
    --line) line="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) die "unknown arg: $1";;
  esac; done

  [[ -n "${model}" && -d "${model}" ]] || die "--model DIR missing/invalid"
  [[ -f "${model}/unigram.tsv" && -f "${model}/bigram.tsv" && -f "${model}/stats.tsv" ]] || die "model incomplete in ${model}"
  if [[ -z "${line:-}" ]]; then
    # read from stdin if not provided
    line="$(cat)"
  fi

  local p25 p50 p75 mad
  p25="$(read_model_stat "${model}" p25)"; p50="$(read_model_stat "${model}" p50)"
  p75="$(read_model_stat "${model}" p75)"; mad="$(read_model_stat "${model}" mad)"

  # Modified AWK to emit contributions
  local AWK_EXPLAIN
  AWK_EXPLAIN="
${AWK_TOKENIZE}
BEGIN{
  FS=\"\\t\"
  while ((getline < UFILE) > 0) { uni[\$1]=\$2; total_uni+=\$2 }
  while ((getline < BFILE) > 0) { bi[\$1 SUBSEP \$2]=\$3; }
  for (k in bi) { split(k,xy,SUBSEP); left=xy[1]; left_total[left]+=bi[k] }
  vocab=length(uni)
}
function tokdown(s) { gsub(/[^[:alnum:]_]+/, \" \", s); return tolower(s) }
function split_tokens(s, arr,    n) { s=tokdown(s); n=split(s, arr, /[[:space:]]+/); return n }
function neglog(p){ return -log(p) }
{
  raw=\$0; n=split_tokens(raw, t)
  nll=0
  printf(\"Line: %s\\n\\nContributions:\\n\", raw)
  for (i=1;i<=n;i++){
    u=t[i]; if(u==\"\") continue
    p_u = ( (uni[u]+1) / (total_uni + vocab) )
    c=neglog(p_u); nll+=c
    printf(\"  %-24s unigram  -log(p)=%.5f (count=%d)\\n\", u, c, (u in uni)?uni[u]:0)
    if (i<n && t[i+1]!=\"\") {
      v=t[i+1]; key=u SUBSEP v
      p_v_u = ( (bi[key]+1) / (left_total[u] + vocab) )
      c=neglog(p_v_u); nll+=c
      printf(\"  %-24s bigram:%-12s -log(p)=%.5f (count=%d)\\n\", u, v, c, (key in bi)?bi[key]:0)
    }
  }
  printf(\"\\nTotal NLL: %.6f\\n\", nll)
}
"
    printf "%s\n" "${line}" | awk -v UFILE="${model}/unigram.tsv" -v BFILE="${model}/bigram.tsv" "${AWK_EXPLAIN}"
}

# --------------- Main -----------------
[[ $# -lt 1 ]] && { usage; exit 1; }
sub="$1"; shift || true

case "${sub}" in
    train)   cmd_train "$@";;
    score)   cmd_score "$@";;
    watch)   cmd_watch "$@";;
    explain) cmd_explain "$@";;
    -h|--help) usage;;
    *) die "unknown subcommand: ${sub}";;
esac
