# Model Directory

This folder is where Sentinel stores its trained model files:

- `unigram.tsv` — token frequency table
- `bigram.tsv` — bigram frequency table
- `stats.tsv` — robust statistics (median, MAD, etc.)

These files are generated when you run:

```bash
./sentinel.sh train --model ./model --input /path/to/logfile
