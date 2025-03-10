// Add your JavaScript here 

document.addEventListener('DOMContentLoaded', function() {
    // Handle likes
    document.querySelectorAll('.like-btn').forEach(button => {
        button.addEventListener('click', function() {
            const postId = this.dataset.postId;
            const likeCount = this.querySelector('.like-count');
            const likeText = this.querySelector('.like-text');
            
            fetch(`/like/${postId}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            })
            .then(response => response.json())
            .then(data => {
                likeCount.textContent = data.likes;
                if (data.status === 'liked') {
                    this.classList.add('liked');
                    likeText.textContent = 'Liked';
                } else {
                    this.classList.remove('liked');
                    likeText.textContent = 'Like';
                }
            });
        });
    });
}); 