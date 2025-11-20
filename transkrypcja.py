import sounddevice as sd
import speech_recognition as sr
import pyautogui
from pynput import keyboard
import numpy as np
from scipy.io.wavfile import write
import os
import threading

# --- Konfiguracja ---
HOTKEY_RECORD = keyboard.Key.shift_l   # Przycisk do nagrywania: lewy Shift
HOTKEY_PASTE = keyboard.Key.enter      # Przycisk do wklejenia: Enter
SAMPLE_RATE = 44100                    # Jakość nagrywania
FILENAME = "temp_recording.wav"        # Nazwa pliku tymczasowego

# --- Zmienne globalne ---
is_recording = False
recorded_frames = []
recording_thread = None

def record_audio():
    """Funkcja do nagrywania audio w osobnym wątku."""
    global recorded_frames
    
    recorded_frames = [] # Resetuj klatki przed nowym nagraniem
    
    def callback(indata, frames, time, status):
        """Wywoływane dla każdego bloku audio."""
        if is_recording:
            recorded_frames.append(indata.copy())

    # Utrzymuj strumień otwarty tak długo, jak trwa nagrywanie
    with sd.InputStream(callback=callback, samplerate=SAMPLE_RATE, channels=1, dtype='float32'):
        while is_recording:
            sd.sleep(100)

def transcribe_and_paste():
    """Transkrybuje nagrany dźwięk i wkleja tekst."""
    if not recorded_frames:
        print("Brak nagrania do transkrypcji.")
        return

    print("Zapisywanie nagrania...")
    # Konwertuj listę klatek na tablicę NumPy
    recording = np.concatenate(recorded_frames, axis=0)
    
    # Konwersja do formatu int16, który jest oczekiwany przez speech_recognition
    # Normalizacja do zakresu int16 (-32768 do 32767)
    recording_int16 = (recording * 32767).astype(np.int16)
    
    # Zapisz nagranie do pliku WAV
    write(FILENAME, SAMPLE_RATE, recording_int16)

    print("Transkrypcja...")
    recognizer = sr.Recognizer()
    try:
        with sr.AudioFile(FILENAME) as source:
            audio_data = recognizer.record(source)
            # Używamy darmowego API Google do rozpoznawania mowy
            text = recognizer.recognize_google(audio_data, language="pl-PL")
            print(f"Rozpoznany tekst: {text}")
            
            # Wklej tekst do aktywnej aplikacji symulując pisanie
            pyautogui.write(text)
            
    except sr.UnknownValueError:
        print("Nie udało się rozpoznać mowy.")
    except sr.RequestError as e:
        print(f"Błąd usługi Google Speech Recognition; {e}")
    finally:
        # Usuń plik tymczasowy po użyciu
        if os.path.exists(FILENAME):
            os.remove(FILENAME)

def on_press(key):
    """Obsługa naciśnięcia klawisza."""
    global is_recording, recording_thread
    
    if key == HOTKEY_RECORD and not is_recording:
        is_recording = True
        print(">>> Rozpoczęto nagrywanie (puść Shift, aby zakończyć)...")
        # Uruchom nagrywanie w osobnym wątku, aby nie blokować reszty skryptu
        recording_thread = threading.Thread(target=record_audio)
        recording_thread.start()

    if key == HOTKEY_PASTE:
        if is_recording:
            print("Najpierw zakończ nagrywanie, puszczając Shift.")
            return
        print(">>> Przetwarzanie i wklejanie tekstu...")
        transcribe_and_paste()


def on_release(key):
    """Obsługa puszczenia klawisza."""
    global is_recording
    if key == HOTKEY_RECORD and is_recording:
        is_recording = False
        print(">>> Zakończono nagrywanie. Naciśnij Enter, aby wkleić tekst.")

# --- Główna część skryptu ---
if __name__ == "__main__":
    print("Skrypt do transkrypcji uruchomiony.")
    print(f"Naciśnij i przytrzymaj lewy Shift, aby nagrywać.")
    print(f"Naciśnij Enter, aby przetworzyć mowę i wkleić tekst.")
    print("Naciśnij Ctrl+C w terminalu, aby zakończyć.")

    # Uruchom nasłuchiwanie klawiszy w tle
    with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()
