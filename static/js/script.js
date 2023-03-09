/* Custom JavaScript */
console.log('Custom JavaScript loaded!');

// Add a confirmation dialog to delete buttons
$('.btn-delete').click(function() {
  return confirm('Are you sure you want to delete this item?');
});

// Add a datepicker to date inputs
$('input[type="date"]').datepicker({
  format: 'yyyy-mm-dd'
});

// Add a timepicker to time inputs
$('input[type="time"]').timepicker({
  timeFormat: 'HH:mm',
  interval: 30,
  minTime: '00:00',
  maxTime: '23:59',
  defaultTime: '12:00',
  startTime: '00:00',
  dynamic: false,
  dropdown: true,
  scrollbar: true
});

