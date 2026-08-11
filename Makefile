PY := python

.PHONY: all list bridge filter score irish visualise report test clean help

# Default target: run the whole pipeline
all:
	$(PY) -m csf_sme_coverage.cli

# List available phases
list:
	$(PY) -m csf_sme_coverage.cli --list

# Individual phase targets
bridge:
	$(PY) -m csf_sme_coverage.cli bridge

filter:
	$(PY) -m csf_sme_coverage.cli filter

score:
	$(PY) -m csf_sme_coverage.cli score

irish:
	$(PY) -m csf_sme_coverage.cli irish_overlay

visualise:
	$(PY) -m csf_sme_coverage.cli visualise

report:
	$(PY) -m csf_sme_coverage.cli report

# Run unit tests
test:
	$(PY) -m pytest -v tests/

# Delete every generated output (keeps raw data intact)
clean:
	rm -rf outputs/*.csv outputs/*.md outputs/*.txt outputs/figures data/processed/*

# Short help
help:
	@echo "Available targets:"
	@echo "  make all        - run the whole pipeline (bridge -> report)"
	@echo "  make list       - list pipeline phases"
	@echo "  make <phase>    - run a single phase (bridge/filter/score/irish/visualise/report)"
	@echo "  make test       - run pytest unit tests"
	@echo "  make clean      - delete generated outputs"
