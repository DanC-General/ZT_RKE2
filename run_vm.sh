sh -c "cd module && make && ./scrape"
sh -c "cd module && source venv/bin/activate && cd Agent && python3 rules.py"
