(function($) {
  showSwal = function(titel, content, Id) {
   Swal.fire({
      title: "<b>"+titel+":</b> "+Id,
      html: "<pre id='pre' style='white-space: pre-wrap;word-wrap: break-word;border-style:solid' class=''>"+content+"</pre>",
      confirmButtonColor: '#d33',
      confirmButtonText: 'Close',
      customClass: 'swal-wide',
      });

     var element = document.getElementById("pre");
     element.classList.add("json_content");
  }

  })(jQuery);