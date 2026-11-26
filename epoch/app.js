
const state = document.getElementById("systemState");
const activate = document.getElementById("activate");

activate.addEventListener("click", () => {
  state.textContent = "EPOCH ONE INITIALISED";
  activate.textContent = "SYSTEM ACTIVE";
  activate.disabled = true;
});

const voiceButton = document.getElementById("voiceButton");
const voiceOutput = document.getElementById("voiceOutput");

voiceButton.addEventListener("click", () => {
  const SpeechRecognition =
    window.SpeechRecognition ||
    window.webkitSpeechRecognition;

  if (!SpeechRecognition) {
    voiceOutput.textContent =
      "Voice recognition is not supported by this browser.";
    return;
  }

  const recognition = new SpeechRecognition();
  recognition.lang = "en-IN";
  recognition.interimResults = false;
  recognition.maxAlternatives = 1;

  voiceOutput.textContent = "Listening...";

  recognition.onresult = (event) => {
    voiceOutput.textContent =
      "You said: " + event.results[0][0].transcript;
  };

  recognition.onerror = (event) => {
    voiceOutput.textContent =
      "Voice error: " + event.error;
  };

  recognition.onend = () => {
    voiceButton.textContent = "START VOICE";
  };

  voiceButton.textContent = "LISTENING...";
  recognition.start();
});

const cameraButton =
  document.getElementById("cameraButton");

const camera = document.getElementById("camera");
const cameraOutput =
  document.getElementById("cameraOutput");

let cameraStream = null;

cameraButton.addEventListener("click", async () => {
  if (cameraStream) {
    cameraStream.getTracks().forEach(track => track.stop());
    cameraStream = null;
    camera.srcObject = null;
    camera.hidden = true;
    cameraButton.textContent = "OPEN CAMERA";
    cameraOutput.textContent = "Camera inactive.";
    return;
  }

  if (!navigator.mediaDevices?.getUserMedia) {
    cameraOutput.textContent =
      "Camera access requires a supported secure browser.";
    return;
  }

  try {
    cameraStream =
      await navigator.mediaDevices.getUserMedia({
        video: { facingMode: "user" },
        audio: false
      });

    camera.srcObject = cameraStream;
    camera.hidden = false;
    cameraButton.textContent = "CLOSE CAMERA";
    cameraOutput.textContent = "Camera active.";
  } catch (error) {
    cameraOutput.textContent =
      "Camera unavailable or permission denied.";
  }
});

const gestureButton =
  document.getElementById("gestureButton");

const gestureOutput =
  document.getElementById("gestureOutput");

gestureButton.addEventListener("click", () => {
  gestureOutput.textContent =
    "Gesture interaction simulated successfully. " +
    "Physical gesture recognition is a future development goal.";
});

const contextButton =
  document.getElementById("contextButton");

const contextOutput =
  document.getElementById("contextOutput");

contextButton.addEventListener("click", () => {
  const hour = new Date().getHours();

  let greeting = "Good evening";

  if (hour < 12) greeting = "Good morning";
  else if (hour < 17) greeting = "Good afternoon";

  contextOutput.textContent =
    greeting + ". EPOCH ONE context demonstration is active.";
});

window.addEventListener("beforeunload", () => {
  if (cameraStream) {
    cameraStream.getTracks().forEach(track => track.stop());
  }
});
