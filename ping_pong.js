const canvas = document.getElementById('gameCanvas');
const ctx = canvas.getContext('2d');
const overlay = document.getElementById('pauseOverlay');

const WIDTH = canvas.width;
const HEIGHT = canvas.height;

const PADDLE_WIDTH = 10;
const PADDLE_HEIGHT = 100;
const BALL_SIZE = 15;
const PADDLE_SPEED = 7;
let ballSpeedX = 5;
let ballSpeedY = 5;

let paused = false;

let leftPaddleY = HEIGHT / 2 - PADDLE_HEIGHT / 2;
let rightPaddleY = HEIGHT / 2 - PADDLE_HEIGHT / 2;
let ballX = WIDTH / 2 - BALL_SIZE / 2;
let ballY = HEIGHT / 2 - BALL_SIZE / 2;

let leftScore = 0;
let rightScore = 0;

const keys = {};

function togglePause() {
  paused = !paused;
  overlay.style.display = paused ? 'flex' : 'none';
  if (!paused) {
    requestAnimationFrame(loop);
  }
}

window.addEventListener('keydown', e => {
  keys[e.key] = true;
  if (e.key.toLowerCase() === 'p') {
    togglePause();
  }
});
window.addEventListener('keyup', e => {
  keys[e.key] = false;
});

overlay.addEventListener('click', togglePause);
canvas.addEventListener('click', () => {
  if (paused) togglePause();
});

// Touch controls for mobile
function handleTouch(e) {
  const rect = canvas.getBoundingClientRect();
  for (const touch of e.touches) {
    const y = touch.clientY - rect.top;
    if (touch.clientX - rect.left < WIDTH / 2) {
      leftPaddleY = y - PADDLE_HEIGHT / 2;
      if (leftPaddleY < 0) leftPaddleY = 0;
      if (leftPaddleY + PADDLE_HEIGHT > HEIGHT) leftPaddleY = HEIGHT - PADDLE_HEIGHT;
    } else {
      rightPaddleY = y - PADDLE_HEIGHT / 2;
      if (rightPaddleY < 0) rightPaddleY = 0;
      if (rightPaddleY + PADDLE_HEIGHT > HEIGHT) rightPaddleY = HEIGHT - PADDLE_HEIGHT;
    }
  }
  e.preventDefault();
}

canvas.addEventListener('touchstart', handleTouch, {passive: false});
canvas.addEventListener('touchmove', handleTouch, {passive: false});

function resetBall() {
  ballX = WIDTH / 2 - BALL_SIZE / 2;
  ballY = HEIGHT / 2 - BALL_SIZE / 2;
  ballSpeedX *= -1;
}

function update() {
  // Left paddle movement (W/S)
  if (keys['w'] && leftPaddleY > 0) {
    leftPaddleY -= PADDLE_SPEED;
  }
  if (keys['s'] && leftPaddleY + PADDLE_HEIGHT < HEIGHT) {
    leftPaddleY += PADDLE_SPEED;
  }
  // Right paddle movement (ArrowUp/ArrowDown)
  if (keys['ArrowUp'] && rightPaddleY > 0) {
    rightPaddleY -= PADDLE_SPEED;
  }
  if (keys['ArrowDown'] && rightPaddleY + PADDLE_HEIGHT < HEIGHT) {
    rightPaddleY += PADDLE_SPEED;
  }

  // Move the ball
  ballX += ballSpeedX;
  ballY += ballSpeedY;

  // Wall collision
  if (ballY <= 0 || ballY + BALL_SIZE >= HEIGHT) {
    ballSpeedY *= -1;
  }

  // Paddle collision
  if (ballX <= 30 + PADDLE_WIDTH &&
      ballY + BALL_SIZE >= leftPaddleY &&
      ballY <= leftPaddleY + PADDLE_HEIGHT &&
      ballSpeedX < 0) {
    ballSpeedX *= -1;
  }
  if (ballX + BALL_SIZE >= WIDTH - 30 - PADDLE_WIDTH &&
      ballY + BALL_SIZE >= rightPaddleY &&
      ballY <= rightPaddleY + PADDLE_HEIGHT &&
      ballSpeedX > 0) {
    ballSpeedX *= -1;
  }

  // Scoring
  if (ballX <= 0) {
    rightScore += 1;
    resetBall();
  }
  if (ballX + BALL_SIZE >= WIDTH) {
    leftScore += 1;
    resetBall();
  }
}

function draw() {
  ctx.fillStyle = 'black';
  ctx.fillRect(0, 0, WIDTH, HEIGHT);

  ctx.fillStyle = 'white';
  ctx.fillRect(30, leftPaddleY, PADDLE_WIDTH, PADDLE_HEIGHT);
  ctx.fillRect(WIDTH - 30 - PADDLE_WIDTH, rightPaddleY, PADDLE_WIDTH, PADDLE_HEIGHT);
  ctx.fillRect(ballX, ballY, BALL_SIZE, BALL_SIZE);

  ctx.fillRect(WIDTH / 2 - 1, 0, 2, HEIGHT);

  ctx.font = '48px sans-serif';
  ctx.fillText(leftScore, WIDTH / 4, 50);
  ctx.fillText(rightScore, WIDTH * 3 / 4, 50);
}

function loop() {
  if (!paused) {
    update();
    draw();
    requestAnimationFrame(loop);
  }
}

loop();
