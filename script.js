// Initialize variables
let visitorCount = localStorage.getItem('visitorCount') || 0;
let isSidebarOpen = window.innerWidth > 768;

// Initialize sidebar state
document.querySelector('.sidebar').classList.toggle('active', isSidebarOpen);

// Form Submission Handler
document.querySelector('.submit-btn').addEventListener('click', () => {
    const firstName = document.getElementById('firstName').value.trim();
    const lastName = document.getElementById('lastName').value.trim();
    
    if (firstName && lastName) {
        const fullName = `${firstName} ${lastName}`;
        
        // Store visitor information
        const visitors = JSON.parse(localStorage.getItem('visitors') || '[]');
        visitors.push({
            name: fullName,
            timestamp: new Date().toISOString()
        });
        localStorage.setItem('visitors', JSON.stringify(visitors));
        
        // Update visitor count
        visitorCount++;
        localStorage.setItem('visitorCount', visitorCount);
        
        // Show invitation with animations
        document.querySelector('.page1').classList.add('hidden');
        setTimeout(() => {
            document.querySelector('.page2').style.display = 'block';
            document.querySelector('#invitationName').innerHTML = 
                `<span style="display:block;animation:fadeIn 1s ease-out">नमस्कार ${fullName},</span>
                 <span style="display:block;animation:fadeIn 1s ease-out 0.5s both">सप्रेम सादर निमंत्रण</span>`;
        }, 1000);

        // Set background image with fade effect
        fetch('https://source.unsplash.com/random/1920x1080/?indian,wedding,traditional')
            .then(response => {
                const img = new Image();
                img.onload = () => {
                    document.querySelector('.page2').style.backgroundImage = `url(${response.url})`;
                    document.querySelector('.page2').style.opacity = '1';
                };
                img.src = response.url;
            });
    }
});

// Enhanced Navigation Handling
document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', () => {
        // Update active link
        document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
        link.classList.add('active');
        
        // Animate sections
        const sectionId = link.dataset.section;
        const currentSection = document.querySelector('.section.active-section');
        currentSection.style.opacity = '0';
        currentSection.style.transform = 'translateY(20px)';
        
        setTimeout(() => {
            document.querySelectorAll('.section').forEach(section => {
                section.classList.remove('active-section');
            });
            
            const newSection = document.getElementById(sectionId);
            newSection.classList.add('active-section');
            
            requestAnimationFrame(() => {
                newSection.style.opacity = '1';
                newSection.style.transform = 'translateY(0)';
            });
        }, 300);

        // Handle mobile sidebar
        if (window.innerWidth <= 768) {
            toggleSidebar(false);
        }
    });
});

// Sidebar Toggle Functionality
const toggleButton = document.querySelector('.toggle-sidebar');
const sidebar = document.querySelector('.sidebar');

function toggleSidebar(force) {
    isSidebarOpen = force !== undefined ? force : !isSidebarOpen;
    sidebar.classList.toggle('active', isSidebarOpen);
    toggleButton.innerHTML = isSidebarOpen ? '×' : '☰';
    toggleButton.style.transform = isSidebarOpen ? 'rotate(180deg)' : 'rotate(0)';
}

toggleButton.addEventListener('click', () => toggleSidebar());

// Close sidebar when clicking outside
document.addEventListener('click', (e) => {
    if (isSidebarOpen && 
        !sidebar.contains(e.target) && 
        !toggleButton.contains(e.target) && 
        window.innerWidth <= 768) {
        toggleSidebar(false);
    }
});

// Countdown Timer with Marathi labels
function updateTimer() {
    const targetDate = new Date('2025-02-13T15:11:00').getTime();
    const now = new Date().getTime();
    const difference = targetDate - now;

    const days = Math.floor(difference / (1000 * 60 * 60 * 24));
    const hours = Math.floor((difference % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    const minutes = Math.floor((difference % (1000 * 60 * 60)) / (1000 * 60));
    const seconds = Math.floor((difference % (1000 * 60)) / 1000);

    document.getElementById('timer').innerHTML = `
        <div class="timer-item">
            <div class="timer-number">${days}</div>
            <div class="timer-label">दिवस</div>
        </div>
        <div class="timer-item">
            <div class="timer-number">${hours}</div>
            <div class="timer-label">तास</div>
        </div>
        <div class="timer-item">
            <div class="timer-number">${minutes}</div>
            <div class="timer-label">मिनिटे</div>
        </div>
        <div class="timer-item">
            <div class="timer-number">${seconds}</div>
            <div class="timer-label">सेकंद</div>
        </div>
    `;
}

// Initialize timer and update every second
updateTimer();
setInterval(updateTimer, 1000);

// Handle Enter Key for Form Submission
document.querySelectorAll('.name-field').forEach(input => {
    input.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            document.querySelector('.submit-btn').click();
        }
    });
});

// Window Resize Handler
window.addEventListener('resize', () => {
    if (window.innerWidth > 768) {
        toggleSidebar(true);
    } else if (window.innerWidth <= 768 && isSidebarOpen) {
        toggleSidebar(false);
    }
});

// Add smooth scrolling for anchor links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        document.querySelector(this.getAttribute('href')).scrollIntoView({
            behavior: 'smooth'
        });
    });
});

// Add background music toggle (optional)
const audioElement = new Audio('path_to_wedding_music.mp3'); // Add your music file
const musicButton = document.createElement('button');
musicButton.classList.add('music-toggle');
musicButton.innerHTML = '🎵';
musicButton.style.position = 'fixed';
musicButton.style.bottom = '20px';
musicButton.style.left = '20px';
musicButton.style.zIndex = '1000';

let isPlaying = false;

musicButton.addEventListener('click', () => {
    if (isPlaying) {
        audioElement.pause();
        musicButton.style.opacity = '0.5';
    } else {
        audioElement.play();
        musicButton.style.opacity = '1';
    }
    isPlaying = !isPlaying;
});

document.body.appendChild(musicButton);
