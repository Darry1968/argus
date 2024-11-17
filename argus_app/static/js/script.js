window.addEventListener('DOMContentLoaded', function() {
    setTimeout(function() {
        // Hide the loader and display content
        var loader = document.getElementById('loader');
        var content = document.getElementById('content');
        
        if (loader && content) {
            loader.style.display = 'none';
            content.style.display = 'block';
        } else {
            console.error("Elements not found: #loader or #content");
        }
    }, 3000); // 2 seconds duration for loader
});
