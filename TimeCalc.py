import subprocess

# Enter the number of seconds here
total_seconds = int(rtime)

# Calculate hours, minutes, and seconds
hours = total_seconds // 3600
minutes = (total_seconds % 3600) // 60
seconds = total_seconds % 60

# Format as HH:MM:SS
formatted_time = f"Total run time: {hours} hr(s) {minutes} min(s) {seconds} sec(s)"
print(formatted_time)

subprocess.run(["python", "main_EmailComplete.py"], formatted_time, check=True)