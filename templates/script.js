// Global variables
let capturing = false;
let totalPackets = 0;
let totalAttacks = 0;
let pollingInterval = null;

// Fetch available network interfaces
async function fetchNetworks() {
    try {
        const response = await axios.get('/networks');
        const interfaces = response.data;
        const select = document.getElementById("networks");

        interfaces.forEach(intf => {
            const option = document.createElement("option");
            option.value = intf;
            option.textContent = intf;
            select.appendChild(option);
        });
    } catch (error) {
        console.error("Error fetching network interfaces: ", error);
        alert("Failed to load network interfaces.");
    }
}

// Start capturing packets
async function startCapture() {
    const networkInterface = document.getElementById("networks").value;
    if (!networkInterface) {
        alert("Please select a network interface.");
        return;
    }

    capturing = true;
    try {
        const response = await axios.post('/start_capture', { interface: networkInterface });
        alert(response.data.status);

        // Clear existing data
        document.getElementById("alertList").innerHTML = "";
        document.getElementById("totalPackets").textContent = "0";
        document.getElementById("totalAttacks").textContent = "0";

        // Initialize the feature container as a table
        initializeFeatureTable();

        totalPackets = 0;
        totalAttacks = 0;

        // Start polling for new packet data every 30 seconds
        fetchPackets(); // Initial fetch
        pollingInterval = setInterval(fetchPackets, 30000); // Then every 30 seconds
    } catch (error) {
        console.error("Error starting capture: ", error);
        alert("Failed to start capture.");
    }
}

// Stop capturing packets
async function stopCapture() {
    capturing = false;
    // Clear the polling interval
    if (pollingInterval) {
        clearInterval(pollingInterval);
        pollingInterval = null;
    }

    try {
        const response = await axios.post('/stop_capture');
        alert(response.data.status);
    } catch (error) {
        console.error("Error stopping capture: ", error);
        alert("Failed to stop capture.");
    }
}

// Initialize the feature container with a table
function initializeFeatureTable() {
    const featureContainer = document.getElementById("featureContainer");
    featureContainer.innerHTML = `
        <table id="featureTable" class="feature-table">
            <thead>
                <tr>
                    <th>Time</th>
                    <th>Source IP</th>
                    <th>Destination IP</th>
                    <th>Protocol</th>
                    <th>Size</th>
                    <th>Prediction</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody id="featureTableBody">
                <!-- Feature rows will be added here -->
            </tbody>
        </table>
    `;
}

// Fetch packets and update the UI
async function fetchPackets() {
    if (!capturing) return;

    try {
        const response = await axios.get('/get_packets');
        const packets = response.data.packets;

        if (packets && packets.length > 0) {
            // Get the feature table body
            const featureTableBody = document.getElementById("featureTableBody");

            // Add new packets to the feature table
            packets.forEach(packet => {
                // Add feature row
                const featureRow = document.createElement("tr");
                featureRow.innerHTML = `
                    <td>${packet.time}</td>
                    <td>${packet.source}</td>
                    <td>${packet.destination}</td>
                    <td>${packet.protocol}</td>
                    <td>${packet.size}</td>
                    <td>${packet.prediction}</td>
                    <td>
                        <button class="btn-details" onclick="toggleDetails(this)" data-details='${JSON.stringify(packet.features)}'>
                            Show Details
                        </button>
                    </td>
                `;

                // Add row at the top of the table
                featureTableBody.insertBefore(featureRow, featureTableBody.firstChild);

                // Add alerts for detected attacks
                if (packet.prediction !== "benign") {
                    addAlertEntry(packet);
                    totalAttacks++;
                }

                totalPackets++;
            });

            // Limit the number of rows to prevent the table from getting too large
            while (featureTableBody.children.length > 50) {
                featureTableBody.removeChild(featureTableBody.lastChild);
            }

            // Update stats
            document.getElementById("totalPackets").textContent = totalPackets;
            document.getElementById("totalAttacks").textContent = totalAttacks;
        }
    } catch (error) {
        console.error("Error fetching packets: ", error);
    }
}

// Toggle showing detailed features
function toggleDetails(button) {
    const details = JSON.parse(button.getAttribute('data-details'));
    const parentRow = button.parentNode.parentNode;

    // Check if details row already exists
    const nextRow = parentRow.nextSibling;
    if (nextRow && nextRow.classList && nextRow.classList.contains('details-row')) {
        // Remove details row if it exists
        nextRow.parentNode.removeChild(nextRow);
        button.textContent = 'Show Details';
    } else {
        // Create new details row
        const detailsRow = document.createElement('tr');
        detailsRow.className = 'details-row';

        // Create details cell that spans all columns
        const detailsCell = document.createElement('td');
        detailsCell.colSpan = 7;

        // Create a table for the details
        let detailsHTML = '<table class="details-table">';
        for (const [key, value] of Object.entries(details)) {
            detailsHTML += `<tr><th>${key}</th><td>${value}</td></tr>`;
        }
        detailsHTML += '</table>';

        detailsCell.innerHTML = detailsHTML;
        detailsRow.appendChild(detailsCell);

        // Insert after the current row
        if (parentRow.nextSibling) {
            parentRow.parentNode.insertBefore(detailsRow, parentRow.nextSibling);
        } else {
            parentRow.parentNode.appendChild(detailsRow);
        }

        button.textContent = 'Hide Details';
    }
}

// Add an alert entry for detected attacks
function addAlertEntry(packet) {
    const alertList = document.getElementById("alertList");
    const alertItem = document.createElement("li");
    alertItem.textContent = `🚨 Detected ${packet.prediction} attack from ${packet.source} to ${packet.destination} at ${packet.time}`;

    // Add a class for styling
    alertItem.className = "alert-item";

    // Add the alert to the top of the list
    alertList.insertBefore(alertItem, alertList.firstChild);

    // Limit the number of alerts shown
    while (alertList.children.length > 20) {
        alertList.removeChild(alertList.lastChild);
    }
}

// Fetch networks on page load
window.onload = fetchNetworks;