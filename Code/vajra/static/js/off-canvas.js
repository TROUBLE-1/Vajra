(function($) {
  'use strict';
  $(function() {
    $('[data-bs-toggle="offcanvas"]').on("click", function() {
      $('.sidebar-offcanvas').toggleClass('active')
    });
  });
})(jQuery);