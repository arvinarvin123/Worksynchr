

    function triggerMonthlyPayroll() {
        if (confirm("Are you sure you want to run this month’s payroll?")) {
        fetch('/Payroll/RunMonthlyPayroll', {
            method: 'POST'
        }).then(response => {
            if (response.ok) {
                alert("Payroll computed and saved successfully.");
                document.getElementById("runMonthlyPayrollBtn").disabled = true;
                location.reload(); // Optional
            } else {
                alert("Something went wrong.");
            }
        });
        }
    }



function updateTime() {
    const now = new Date();
    const timeString = now.toLocaleTimeString([], {hour: '2-digit', minute: '2-digit', second: '2-digit' });
    document.getElementById('punchInTime').textContent = timeString;
    document.getElementById('punchOutTime').textContent = timeString;
    }
    setInterval(updateTime, 1000);
    updateTime(); // Initial call






    document.getElementById('btn-punchin').addEventListener('click', function (e) {
        e.preventDefault(); // Pause form until permission/location is resolved

    if (!navigator.geolocation || !navigator.permissions) {
        alert("Geolocation is not supported by your browser.");
    return;
                }

    navigator.permissions.query({name: 'geolocation' }).then(function (result) {
                    if (result.state === 'granted') {
        getLocationAndSubmit();
                    } else if (result.state === 'prompt') {
        // Ask the user now
        navigator.geolocation.getCurrentPosition(
            function (position) {
                setLatLngAndSubmit(position);
            },
            function (error) {
                alert("Please allow location access to punch in.");
            }
        );
                    } else if (result.state === 'denied') {
        alert("Location access has been denied. Please enable it in your browser settings.");
                    }
                });
            });

    function getLocationAndSubmit() {
        navigator.geolocation.getCurrentPosition(function (position) {
            setLatLngAndSubmit(position);
        }, function (error) {
            alert("Unable to fetch your location. Please try again.");
        });
            }

    function setLatLngAndSubmit(position) {
        document.getElementById('latitude').value = position.coords.latitude;
    document.getElementById('longitude').value = position.coords.longitude;
    document.getElementById('punchInForm').submit();
}


//
const viewModal = document.getElementById('viewNoticeModal');
viewModal.addEventListener('show.bs.modal', function (event) {
    const button = event.relatedTarget;
    document.getElementById('modalTitle').textContent = button.getAttribute('data-title');
    document.getElementById('modalMessage').textContent = button.getAttribute('data-message');
    document.getElementById('modalCategory').textContent = button.getAttribute('data-category');
    document.getElementById('modalPosted').textContent = button.getAttribute('data-posted');
    document.getElementById('modalExpiry').textContent = button.getAttribute('data-expiry');
});


//

document.addEventListener('DOMContentLoaded', function () {
    // Get the target type dropdown and the fields
    const targetTypeSelect = document.getElementById('targetTypeSelect');
    const departmentField = document.getElementById('departmentField');
    const employeeField = document.getElementById('employeeField');

    // Add the change event listener to the select element
    targetTypeSelect.addEventListener('change', function () {
        const targetType = this.value;

        // Show/hide fields based on the selected TargetType
        if (targetType === 'Department') {
            departmentField.style.display = 'block';
            employeeField.style.display = 'none';
        } else if (targetType === 'Employee') {
            departmentField.style.display = 'none';
            employeeField.style.display = 'block';
        } else {
            departmentField.style.display = 'none';
            employeeField.style.display = 'none';
        }
    });

    // Trigger change event on page load to set the initial state
    targetTypeSelect.dispatchEvent(new Event('change'));
});


$(document).ready(function() {
    // Add form submission handler
    $('form').on('submit', function(e) {
        if (!confirm('Are you sure you want to save changes to this employee?')) {
            e.preventDefault();
        }
    });
});