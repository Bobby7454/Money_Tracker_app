document.addEventListener('DOMContentLoaded', function() {
    // Function to fetch and display records
    function fetchRecords() {
        fetch('/expenses')
            .then(response => response.json())
            .then(data => {
                const expensesTableBody = document.getElementById('expenses_table_body');
                const totalAmountCell = document.getElementById('total-amount');
                expensesTableBody.innerHTML = ''; // Clear existing rows
    
                let totalIncome = 0;
                let totalExpenses = 0;
    
                data.forEach(record => {
                    const newRow = expensesTableBody.insertRow();
                    const categoryCell = newRow.insertCell();
                    const amountCell = newRow.insertCell();
                    const infoCell = newRow.insertCell();
                    const dateCell = newRow.insertCell();
                    const deleteCell = newRow.insertCell();
    
                    const deleteBtn = document.createElement('button');
                    deleteBtn.textContent = 'Delete';
                    deleteBtn.classList.add('btn-delete');
                    deleteBtn.addEventListener('click', function() {
                        deleteRecord(record._id);
                    });
    
                    categoryCell.textContent = record.category;
                    amountCell.textContent = record.amount;
                    infoCell.textContent = record.info;
                    dateCell.textContent = new Date(record.date).toISOString().split('T')[0]; // Format the date
                    deleteCell.appendChild(deleteBtn);
    
                    // Calculate total income and expenses
                    if (record.category === 'income') {
                        totalIncome += record.amount;
                    } else if (record.category === 'expense') {
                        totalExpenses += record.amount;
                    }
                });
    
                // Calculate total amount
                const totalAmount = totalIncome - totalExpenses;
                totalAmountCell.textContent = totalAmount.toFixed(2); // Ensure two decimal places
            })
            .catch(error => {
                console.error('Error fetching expenses:', error);
                alert('Error fetching expenses');
            });
    }
    document.addEventListener('DOMContentLoaded', function() {
        // Assuming you get the user's name from a server-side script or a local storage
        const userName = 'John Doe'; // Replace with actual user name retrieval logic
        document.getElementById('userName').textContent = userName;
    });
    
    
    

    // Function to add a record
    const addRecordForm = document.querySelector('#addRecordForm');
    addRecordForm.addEventListener('submit', function(event) {
        event.preventDefault();

        const category = document.querySelector('#category_select').value;
        const amount = document.querySelector('#amount_input').value;
        const info = document.querySelector('#info').value;
        const date = document.querySelector('#date_input').value;

        fetch('/add', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                category_select: category,
                amount_input: amount,
                info: info,
                date_input: date
            })
        })
        .then(response => response.text())
        .then(result => {
            console.log(result);
            fetchRecords(); // Refresh records after adding
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Error adding record');
        });
    });

    // Function to delete a record
    function deleteRecord(id) {
        fetch(`/delete/${id}`, {
            method: 'DELETE',
        })
        .then(response => {
            if (response.ok) {
                console.log('Record Deleted Successfully');
                fetchRecords(); // Refresh the records list after deletion
            } else {
                return response.text().then(text => {
                    throw new Error(text);
                });
            }
        })
        .catch(error => {
            console.error('Error deleting record:', error);
            alert('Error deleting record');
        });
    }

    // Initial fetch of records when the page loads
    fetchRecords();
});