/* ==========================================================================
   Allsafe Cybersecurity — site-wide behaviour
   Vanilla JS, no dependencies. Two jobs only:
     1. mobile navigation toggle
     2. mark the current page in the nav
   ========================================================================== */
(function () {
  'use strict';

  /* ---- 1. Mobile nav toggle -------------------------------------------- */
  var toggle = document.querySelector('.nav-toggle');
  var nav = document.querySelector('.nav');

  if (toggle && nav) {
    toggle.addEventListener('click', function () {
      var open = nav.classList.toggle('is-open');
      toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    });

    // Close the panel when a link is followed or the viewport grows.
    nav.addEventListener('click', function (e) {
      if (e.target.tagName === 'A') {
        nav.classList.remove('is-open');
        toggle.setAttribute('aria-expanded', 'false');
      }
    });

    window.addEventListener('resize', function () {
      if (window.innerWidth > 760 && nav.classList.contains('is-open')) {
        nav.classList.remove('is-open');
        toggle.setAttribute('aria-expanded', 'false');
      }
    });
  }

  /* ---- 2. Active nav link ---------------------------------------------- */
  // Compare the last path segment so the same markup works at / and /index.html
  var here = window.location.pathname.split('/').pop() || 'index.html';
  Array.prototype.forEach.call(document.querySelectorAll('.nav a[href]'), function (link) {
    var target = link.getAttribute('href').split('/').pop();
    if (target === here && !link.classList.contains('btn')) {
      link.classList.add('is-active');
      link.setAttribute('aria-current', 'page');
    }
  });

  /* ---- 3. Year stamp in the footer ------------------------------------- */
  var year = document.querySelector('[data-year]');
  if (year) { year.textContent = new Date().getFullYear(); }
})();
