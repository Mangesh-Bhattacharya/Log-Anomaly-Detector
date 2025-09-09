#!/usr/bin/env bats

setup() {
  mkdir -p tmp_model
  cat > sample.log <<'EOF'
Jan  1 host sshd[1]: Accepted password for alice from 10.0.0.1 port 1111 ssh2
Jan  1 host sshd[1]: Accepted password for bob from 10.0.0.2 port 2222 ssh2
EOF
}

teardown() {
  rm -rf tmp_model sample.log scored.log
}

@test "train builds model files" {
  run ./sentinel.sh train --model tmp_model --input sample.log
  [ "$status" -eq 0 ]
  [ -f tmp_model/unigram.tsv ]
  [ -f tmp_model/bigram.tsv ]
  [ -f tmp_model/stats.tsv ]
}

@test "score produces lines and z-scores" {
  ./sentinel.sh train --model tmp_model --input sample.log
  run ./sentinel.sh score --model tmp_model --input sample.log
  [ "$status" -eq 0 ]
}
