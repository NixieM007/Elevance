import os
import shutil
import threading
import queue
import tkinter as tk
from tkinter import messagebox, ttk, filedialog


# Fixed paths
SOURCE_DIR = r"\\test\test\test\test\Inbound Test"
DEST_BASE_DIR = r"\\test\test\test\test\Outbound Test"


# Color theme
BG_BLUE = "#001A33"
FRAME_BLUE = "#084298"
WHITE = "#FFFFFF"
ENTRY_BG = "#F8F9FA"
BUTTON_BLUE = "#C8DCF8"


def center_window(root, width, height):
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = int((screen_width / 2) - (width / 2))
    y = int((screen_height / 2) - (height / 2))
    root.geometry(f"{width}x{height}+{x}+{y}")


def get_source_items(source_dir):
    if not os.path.exists(source_dir):
        raise FileNotFoundError(f"Source folder not found:\n{source_dir}")
    return os.listdir(source_dir)


def worker_move_files(files, source_dir, dest_dir, progress_queue):
    moved_count = 0
    errors = []
    total_files = len(files)

    for index, file_name in enumerate(files, start=1):
        src_path = os.path.join(source_dir, file_name)
        dest_path = os.path.join(dest_dir, file_name)

        try:
            shutil.copy(src_path, dest_path)
            # shutil.move(src_path, dest_path)
            moved_count += 1
        except Exception as e:
            errors.append(f"{file_name}: {e}")

        percent = int((index / total_files) * 100)
        progress_queue.put({
            "type": "progress",
            "current": index,
            "total": total_files,
            "percent": percent,
            "file_name": file_name
        })

    progress_queue.put({
        "type": "done",
        "moved_count": moved_count,
        "total_files": total_files,
        "errors": errors
    })


def create_ui():
    root = tk.Tk()
    root.title("Provider Insights (Pi) --> Copy Files Utility")

    screen_w = root.winfo_screenwidth()
    screen_h = root.winfo_screenheight()
    win_w = int(screen_w * 0.65)
    win_h = int(screen_h * 0.9)
    center_window(root, win_w, win_h)

    root.resizable(False, False)
    root.configure(bg=BG_BLUE)

    title_bar = tk.Frame(root, bg=FRAME_BLUE, height=40)
    title_bar.pack(fill="x", padx=8, pady=8)
    title_bar.pack_propagate(False)

    def start_move(event):
        root._drag_x = event.x
        root._drag_y = event.y

    def on_move(event):
        x = root.winfo_pointerx() - root._drag_x
        y = root.winfo_pointery() - root._drag_y
        root.geometry(f"+{x}+{y}")

    window_title = tk.Label(
        title_bar,
        text="Provider Insights (Pi) --> Copy Files Utility",
        font=("Segoe UI", 14, "bold"),
        bg=BUTTON_BLUE,
        fg=BG_BLUE,
        anchor="center"
    )
    window_title.pack(fill="both", expand=True, pady=4)

    title_bar.bind("<Button-1>", start_move)
    title_bar.bind("<B1-Motion>", on_move)
    window_title.bind("<Button-1>", start_move)
    window_title.bind("<B1-Motion>", on_move)

    style = ttk.Style()
    style.theme_use("default")
    style.configure(
        "Blue.Horizontal.TProgressbar",
        troughcolor=WHITE,
        background=BUTTON_BLUE,
        bordercolor=FRAME_BLUE,
        lightcolor=BUTTON_BLUE,
        darkcolor=BUTTON_BLUE
    )

    outer_frame = tk.Frame(root, bg=FRAME_BLUE, bd=4, relief="solid")
    outer_frame.pack(fill="both", expand=True, padx=8, pady=8)

    main_frame = tk.Frame(outer_frame, bg=BG_BLUE, padx=15, pady=15)
    main_frame.pack(fill="both", expand=True)

    title_label = tk.Label(
        main_frame,
        text="Files to Be Copied",
        font=("Segoe UI", 14, "bold"),
        bg=BG_BLUE,
        fg=WHITE
    )
    title_label.pack(pady=(0, 14))

    list_frame = tk.Frame(main_frame, bg=BG_BLUE, height=300)
    list_frame.pack(fill="both", expand=False, pady=(0, 14))
    list_frame.pack_propagate(False)

    scrollbar = tk.Scrollbar(list_frame)
    scrollbar.pack(side="right", fill="y")

    file_listbox = tk.Listbox(
        list_frame,
        yscrollcommand=scrollbar.set,
        font=("Segoe UI", 12),
        bg=WHITE,
        fg="black",
        selectbackground=BUTTON_BLUE,
        selectforeground=WHITE,
        relief="flat",
        bd=0
    )
    file_listbox.pack(side="left", fill="both", expand=True)
    scrollbar.config(command=file_listbox.yview)

    status_label = tk.Label(
        main_frame,
        text="",
        anchor="center",
        bg=BG_BLUE,
        fg=WHITE,
        font=("Segoe UI", 12)
    )
    status_label.pack(fill="x", pady=(0, 8))

    source_label = tk.Label(
        main_frame,
        text="Enter source folder:",
        bg=BG_BLUE,
        fg=WHITE,
        font=("Segoe UI", 12)
    )
    source_label.pack(anchor="w")

    source_entry = tk.Entry(
        main_frame,
        font=("Segoe UI", 12),
        bg=ENTRY_BG,
        fg="black",
        insertbackground="black",
        relief="flat"
    )
    source_entry.pack(fill="x", pady=(5, 8), ipady=4)
    source_entry.insert(0, SOURCE_DIR)

    source_button_row = tk.Frame(main_frame, bg=BG_BLUE)
    source_button_row.pack(fill="x", pady=(0, 12))

    folder_label = tk.Label(
        main_frame,
        text="Enter destination folder:",
        bg=BG_BLUE,
        fg=WHITE,
        font=("Segoe UI", 12)
    )
    folder_label.pack(anchor="w")

    folder_entry = tk.Entry(
        main_frame,
        font=("Segoe UI", 12),
        bg=ENTRY_BG,
        fg="black",
        insertbackground="black",
        relief="flat"
    )
    folder_entry.pack(fill="x", pady=(5, 8), ipady=4)
    folder_entry.insert(0, DEST_BASE_DIR)

    destination_button_row = tk.Frame(main_frame, bg=BG_BLUE)
    destination_button_row.pack(fill="x", pady=(0, 12))

    # This frame is intentionally placed above the progress area.
    # Buttons are added later after on_submit and on_cancel are defined.
    button_frame = tk.Frame(main_frame, bg=BG_BLUE)
    button_frame.pack(anchor="center", pady=(4, 14))

    progress_label = tk.Label(
        main_frame,
        text="Progress: 0 of 0 (0% complete)",
        anchor="w",
        bg=BG_BLUE,
        fg=WHITE,
        font=("Segoe UI", 12, "bold")
    )
    progress_label.pack(fill="x", pady=(0, 5))

    progress_bar = ttk.Progressbar(
        main_frame,
        style="Blue.Horizontal.TProgressbar",
        orient="horizontal",
        mode="determinate",
        length=100
    )
    progress_bar.pack(fill="x", pady=(0, 8))

    current_file_label = tk.Label(
        main_frame,
        text="Current file: None",
        anchor="w",
        bg=BG_BLUE,
        fg=WHITE,
        font=("Segoe UI", 12)
    )
    current_file_label.pack(fill="x", pady=(0, 12))

    countdown_label = tk.Label(
        main_frame,
        text="",
        anchor="center",
        justify="center",
        bg=BG_BLUE,
        fg=WHITE,
        font=("Segoe UI", 12, "bold")
    )
    countdown_label.pack(fill="x", pady=(0, 12))

    progress_queue = queue.Queue()

    small_button_style = {
        "font": ("Segoe UI", 10, "bold"),
        "bg": BUTTON_BLUE,
        "fg": FRAME_BLUE,
        "activebackground": FRAME_BLUE,
        "activeforeground": WHITE,
        "relief": "flat",
        "bd": 0,
        "padx": 10,
        "pady": 5
    }

    main_button_style = {
        "font": ("Segoe UI", 10, "bold"),
        "bg": BUTTON_BLUE,
        "fg": FRAME_BLUE,
        "activebackground": FRAME_BLUE,
        "activeforeground": WHITE,
        "relief": "flat",
        "bd": 0,
        "padx": 12,
        "pady": 8
    }

    def load_files():
        file_listbox.delete(0, tk.END)

        try:
            source_dir = source_entry.get().strip() or SOURCE_DIR
            files = get_source_items(source_dir)

            if files:
                for name in files:
                    file_listbox.insert(tk.END, name)
                status_label.config(text=f"{len(files)} item(s) found in source folder.")
                progress_label.config(text=f"Progress: 0 of {len(files)} (0% complete)")
            else:
                status_label.config(text="No files found in source folder.")
                progress_label.config(text="Progress: 0 of 0 (0% complete)")
        except Exception as e:
            status_label.config(text="Error loading source folder.")
            messagebox.showerror("Error", str(e), parent=root)

    def browse_source_folder():
        selected_folder = filedialog.askdirectory(
            title="Select Source Folder",
            initialdir=source_entry.get().strip() or SOURCE_DIR,
            parent=root
        )

        if selected_folder:
            source_entry.delete(0, tk.END)
            source_entry.insert(0, selected_folder)
            load_files()

    def browse_destination_folder():
        selected_folder = filedialog.askdirectory(
            title="Select Destination Folder",
            initialdir=folder_entry.get().strip() or DEST_BASE_DIR,
            parent=root
        )

        if selected_folder:
            folder_entry.delete(0, tk.END)
            folder_entry.insert(0, selected_folder)

    browse_source_button = tk.Button(
        source_button_row,
        text="Browse",
        command=browse_source_folder,
        **small_button_style
    )
    browse_source_button.pack(side="left")

    refresh_source_button = tk.Button(
        source_button_row,
        text="Refresh Files",
        command=load_files,
        **small_button_style
    )
    refresh_source_button.pack(side="left", padx=(8, 0))

    browse_destination_button = tk.Button(
        destination_button_row,
        text="Browse",
        command=browse_destination_folder,
        **small_button_style
    )
    browse_destination_button.pack(side="left")

    def start_close_countdown(seconds):
        def update_countdown(remaining):
            minutes = remaining // 60
            secs = remaining % 60
            countdown_label.config(
                text=f"Closing automatically in {minutes}:{secs:02d}"
            )

            if remaining > 0:
                root.after(1000, update_countdown, remaining - 1)
            else:
                root.destroy()

        update_countdown(seconds)

    def poll_progress():
        try:
            while True:
                msg = progress_queue.get_nowait()

                if msg["type"] == "progress":
                    current = msg["current"]
                    total = msg["total"]
                    percent = msg["percent"]
                    file_name = msg["file_name"]

                    progress_bar["maximum"] = total
                    progress_bar["value"] = current
                    current_file_label.config(text=f"Current file: {file_name}")
                    progress_label.config(
                        text=f"Progress: {current} of {total} ({percent}% complete)"
                    )
                    status_label.config(text=f"Copying: {file_name}")

                elif msg["type"] == "done":
                    moved_count = msg["moved_count"]
                    total_files = msg["total_files"]
                    errors = msg["errors"]

                    status_label.config(text="Copy completed.")
                    current_file_label.config(text="Current file: Complete")
                    progress_label.config(
                        text=f"Progress: {total_files} of {total_files} (100% complete)"
                    )

                    file_listbox.delete(0, tk.END)
                    load_files()

                    copy_button.config(state="normal")
                    cancel_button.config(state="normal")
                    folder_entry.config(state="normal")
                    browse_destination_button.config(state="normal")
                    source_entry.config(state="normal")
                    browse_source_button.config(state="normal")
                    refresh_source_button.config(state="normal")
                    close_now_button.pack(side="left", padx=(8, 0))

                    if errors:
                        messagebox.showwarning(
                            "Completed with Errors",
                            f"Copy finished.\n\nCopied: {moved_count}\nFailed: {len(errors)}\n\n"
                            + "\n".join(errors[:15]),
                            parent=root
                        )
                        status_label.config(text="Completed with errors.")
                    else:
                        messagebox.showinfo(
                            "Completed Successfully",
                            f"All files were copied successfully.\n\nTotal copied: {moved_count}",
                            parent=root
                        )
                        status_label.config(text="Completed successfully.")

                    start_close_countdown(120)
        except queue.Empty:
            pass

        root.after(100, poll_progress)

    def on_submit():
        source_dir = source_entry.get().strip() or SOURCE_DIR
        dest_dir = folder_entry.get().strip() or DEST_BASE_DIR

        try:
            files = get_source_items(source_dir)
        except Exception as e:
            messagebox.showerror("Error", str(e), parent=root)
            return

        if not files:
            messagebox.showinfo("No Files", "No files found in the source directory.", parent=root)
            return

        if not os.path.exists(dest_dir):
            create_folder = messagebox.askyesno(
                "Create Destination Folder",
                f"The destination folder does not exist:\n{dest_dir}\n\n"
                "Create it and use it as the destination folder?",
                parent=root
            )

            if not create_folder:
                return

            try:
                os.makedirs(dest_dir, exist_ok=True)
            except Exception as e:
                messagebox.showerror(
                    "Error",
                    f"Could not create destination folder:\n{e}",
                    parent=root
                )
                return
        elif not os.path.isdir(dest_dir):
            messagebox.showerror(
                "Invalid Destination",
                f"The destination path exists but is not a folder:\n{dest_dir}",
                parent=root
            )
            return

        confirm = messagebox.askyesno(
            "Confirm Copy",
            f"{len(files)} item(s) will be copied to:\n{dest_dir}\n\nProceed?",
            parent=root
        )

        if not confirm:
            return

        copy_button.config(state="disabled")
        cancel_button.config(state="disabled")
        folder_entry.config(state="disabled")
        browse_destination_button.config(state="disabled")
        source_entry.config(state="disabled")
        browse_source_button.config(state="disabled")
        refresh_source_button.config(state="disabled")

        progress_bar["maximum"] = len(files)
        progress_bar["value"] = 0
        current_file_label.config(text="Current file: Starting...")
        progress_label.config(text=f"Progress: 0 of {len(files)} (0% complete)")
        status_label.config(text="Starting file copy...")

        thread = threading.Thread(
            target=worker_move_files,
            args=(files, source_dir, dest_dir, progress_queue),
            daemon=True
        )
        thread.start()

    def on_cancel():
        root.destroy()

    # Buttons are created here so on_submit and on_cancel already exist,
    # while button_frame still displays above the progress bar.
    close_now_button = tk.Button(
        button_frame,
        text="Close Now",
        command=root.destroy,
        **main_button_style
    )

    copy_button = tk.Button(
        button_frame,
        text="Copy Files",
        command=on_submit,
        **main_button_style
    )
    copy_button.pack(side="left", padx=(0, 8))

    cancel_button = tk.Button(
        button_frame,
        text="Cancel",
        command=on_cancel,
        **main_button_style
    )
    cancel_button.pack(side="left")

    close_now_button.pack(side="left", padx=(8, 0))
    close_now_button.pack_forget()

    load_files()
    poll_progress()
    root.mainloop()


if __name__ == "__main__":
    create_ui()
