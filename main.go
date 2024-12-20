package main

import (
	"database/sql"
	"encoding/json"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
	"log"
	"os" // Added import

	"net/http"
	"strconv"
)

// User struct holds user data
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	UserType string `json:"user_type"`
}

// Order struct holds order data
type Order struct {
	ID              int    `json:"id"`
	PickupLocation  string `json:"pickup_location"`
	DropoffLocation string `json:"dropoff_location"`
	PackageDetails  string `json:"package_details"`
	DeliveryTime    string `json:"delivery_time,omitempty"`
	UserID          int    `json:"user_id"`
	Status          string `json:"status"`
	CourierID       int    `json:"courier_id,omitempty"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

// dbConn creates and returns a connection to the database
func dbConn() (db *sql.DB) {
    dbDriver := "mysql"
    dbUser := os.Getenv("DB_USER")
    dbPass := os.Getenv("DB_PASSWORD")
    dbHost := os.Getenv("DB_HOST")
    dbPort := os.Getenv("DB_PORT")
    dbName := os.Getenv("DB_NAME")

    dsn := dbUser + ":" + dbPass + "@tcp(" + dbHost + ":" + dbPort + ")/" + dbName
    db, err := sql.Open(dbDriver, dsn)
    if err != nil {
        log.Fatal("Database connection error: ", err)
    }

    // It's good practice to ping the database to ensure the connection is valid
    err = db.Ping()
    if err != nil {
        log.Fatal("Database ping error: ", err)
    }

    return db
}


// start the HTTP server and defines routes
func main() {
	log.Println("Server started on: http://localhost:4300")
	http.HandleFunc("/register", handleCORS(Register))
	http.HandleFunc("/login", handleCORS(Login))

	http.HandleFunc("/create-order", handleCORS(CreateOrder))
	http.HandleFunc("/get-user-orders", handleCORS(GetUserOrders))
	http.HandleFunc("/get-order-details", handleCORS(GetOrderDetails))
	http.HandleFunc("/delete-order", handleCORS(DeleteOrder))

	http.HandleFunc("/get-courier-orders", handleCORS(getCourierOrders))
	http.HandleFunc("/update-order-status", handleCORS(updateOrderStatus))
	http.HandleFunc("/decline-order", handleCORS(declineOrder))
	http.HandleFunc("/accept-order", handleCORS(acceptOrder))
	http.HandleFunc("/get-accepted-orders", handleCORS(getAcceptedOrders))

	http.HandleFunc("/get-orders", handleCORS(getOrders))
	http.HandleFunc("/update-order-status-admin", handleCORS(updateOrderStatusAdmin))
	http.HandleFunc("/delete-order-admin", handleCORS(deleteOrderAdmin))
	http.HandleFunc("/assign-order", handleCORS(reassignCourier))
	http.HandleFunc("/get-couriers", handleCORS(getAllCouriers))
    
	http.HandleFunc("/health", handleCORS(HealthCheck))
	
	log.Fatal(http.ListenAndServe("0.0.0.0:4300", nil))

	
}

// handleCORS middleware to handle CORS
func handleCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:4200")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// Handle preflight requests
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	}
}

// HealthCheck handler
func HealthCheck(w http.ResponseWriter, r *http.Request) {
    db := dbConn()
    defer db.Close()
    
    err := db.Ping()
    if err != nil {
        log.Printf("HealthCheck failed: %v", err)
        http.Error(w, "Database not reachable", http.StatusServiceUnavailable)
        return
    }
    
    w.WriteHeader(http.StatusOK)
    w.Write([]byte("OK"))
}



// Register handles user registration
func Register(w http.ResponseWriter, r *http.Request) {

	if r.Method == http.MethodPost {
		var user User

		// Decode the JSON request body into the User struct
		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			http.Error(w, "Invalid request payload", http.StatusBadRequest)
			return
		}

		defer r.Body.Close()

		db := dbConn()
		defer db.Close()

		// Validate required fields
		if user.Username == "" || user.Password == "" || user.Email == "" || user.Phone == "" {
			http.Error(w, "All fields are required", http.StatusBadRequest)
			return
		}

		var id int

		// Check if the username already exists in the database
		err = db.QueryRow("SELECT id FROM users WHERE username=?", user.Username).Scan(&id)
		if err == nil {
			http.Error(w, "Username already exists", http.StatusConflict)
			return
		}

		// Check if the email already exists in the database
		err = db.QueryRow("SELECT id FROM users WHERE email=?", user.Email).Scan(&id)
		if err == nil {
			http.Error(w, "Email already exists", http.StatusConflict)
			return
		}

		// Hash the user's password for secure storage before saving
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Error hashing password", http.StatusInternalServerError)
			return
		}

		// insert new user sql query
		//insForm, err := db.Prepare("INSERT INTO users(username, password, email, phone) VALUES(?, ?, ?, ?)")
		var insForm *sql.Stmt
		if user.UserType == "courier" {
			insForm, err = db.Prepare("INSERT INTO courier(name, password, email, phone) VALUES(?, ?, ?, ?)")
		} else {
			insForm, err = db.Prepare("INSERT INTO users(username, password, email, phone) VALUES(?, ?, ?, ?)")
		}
		//if err != nil {
		//	http.Error(w, "Error preparing query", http.StatusInternalServerError)
		//	return
		//}
		//// Execute the prepared statement
		//_, err = insForm.Exec(user.Username, hashedPassword, user.Email, user.Phone)
		//if err != nil {
		//	http.Error(w, "Error creating user", http.StatusInternalServerError)
		//	return
		//}

		if err != nil {
			log.Printf("Error preparing query: %v", err)
			http.Error(w, "Error preparing query", http.StatusInternalServerError)
			return
		}

		// execute query
		_, err = insForm.Exec(user.Username, hashedPassword, user.Email, user.Phone)
		if err != nil {
			log.Printf("Error executing query: %v", err)
			http.Error(w, "Error creating user", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"message": "User registered successfully"})
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// Login handles user login
func Login(w http.ResponseWriter, r *http.Request) {

	if r.Method == http.MethodPost {
		var user User

		// Decode the JSON request body into the User struct
		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			http.Error(w, "Invalid request payload", http.StatusBadRequest)
			return
		}

		defer r.Body.Close()

		email := user.Email
		password := user.Password

		// Validate that email and password are provided
		if email == "" || password == "" {
			http.Error(w, "Email and password are required", http.StatusBadRequest)
			return
		}

		db := dbConn()
		defer db.Close()

		var storedUser User
		var tableName string

		// Check in "users" table first
		err = db.QueryRow("SELECT id,username, password FROM users WHERE email=?", email).Scan(&storedUser.ID, &storedUser.Username, &storedUser.Password)
		if err == sql.ErrNoRows {
			// If not found, check in "courier" table
			err = db.QueryRow("SELECT courier_id AS id,name,password FROM courier WHERE email=?", email).Scan(&storedUser.ID, &storedUser.Username, &storedUser.Password)
			if err == sql.ErrNoRows {
				// If still not found, check in "admin" table
				err = db.QueryRow("SELECT id AS id,username, password FROM admin WHERE email=?", email).Scan(&storedUser.ID, &storedUser.Username, &storedUser.Password)
				if err == sql.ErrNoRows {
					http.Error(w, "User not found", http.StatusUnauthorized)
					return
				} else if err != nil {
					log.Println("Database query error (admin table):", err)
					http.Error(w, "Database error", http.StatusInternalServerError)
					return
				}
				tableName = "admin"
			} else if err != nil {
				log.Println("Database query error (courier table):", err)
				http.Error(w, "Database error", http.StatusInternalServerError)
				return
			} else {
				tableName = "courier"
			}
		} else if err != nil {
			log.Println("Database query error (user table):", err)
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		} else {
			tableName = "user"
		}

		// Compare the provided password with the stored hashed password
		err = bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(password))
		if err != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		// login successfull
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message":  "Login successful",
			"userId":   storedUser.ID,
			"userType": tableName,
			"username": storedUser.Username,
		})
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// User fFeatures

// CreateOrder handles new order creation
func CreateOrder(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var order Order

		err := json.NewDecoder(r.Body).Decode(&order)
		if err != nil {
			http.Error(w, "Invalid request payload", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		// Check for required fields
		if order.PickupLocation == "" || order.DropoffLocation == "" || order.PackageDetails == "" || order.UserID == 0 {
			http.Error(w, "Missing required fields", http.StatusBadRequest)
			return
		}

		db := dbConn()
		defer db.Close()

		// insert new order query
		insForm, err := db.Prepare("INSERT INTO `orders` (pickup_location, dropoff_location, package_details, delivery_time, user_id, status) VALUES (?, ?, ?, ?, ?, ?)")
		if err != nil {
			http.Error(w, "Error preparing query", http.StatusInternalServerError)
			return
		}
		defer insForm.Close()

		// Set default order status to "Pending"
		order.Status = "Pending"

		// execute query
		_, err = insForm.Exec(order.PickupLocation, order.DropoffLocation, order.PackageDetails, order.DeliveryTime, order.UserID, order.Status)
		if err != nil {
			println(err.Error())
			http.Error(w, "Error creating order", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"message": "Order created successfully"})
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// GetUserOrders handles fetching orders for a specific user
func GetUserOrders(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		userID := r.URL.Query().Get("user_id")
		if userID == "" {
			http.Error(w, "User ID is required", http.StatusBadRequest)
			return
		}

		db := dbConn()
		defer db.Close()

		// Query to fetch all orders for the specified user
		rows, err := db.Query("SELECT order_id, pickup_location, dropoff_location, package_details, delivery_time, status, courier_id, created_at, updated_at, user_id FROM `orders` WHERE user_id = ?", userID)
		if err != nil {
			http.Error(w, "Error fetching orders", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var orders []Order

		// Loop through rows and scan each order's data into an Order struct
		for rows.Next() {
			var order Order
			var deliveryTime sql.NullString
			var courierID sql.NullInt64

			err := rows.Scan(
				&order.ID, &order.PickupLocation, &order.DropoffLocation,
				&order.PackageDetails, &deliveryTime, &order.Status,
				&courierID, &order.CreatedAt, &order.UpdatedAt, &order.UserID,
			)
			if err != nil {
				http.Error(w, "Error scanning order data", http.StatusInternalServerError)
				return
			}

			// Handle nullable fields
			if deliveryTime.Valid {
				order.DeliveryTime = deliveryTime.String
			}
			if courierID.Valid {
				order.CourierID = int(courierID.Int64)
			}

			orders = append(orders, order)
		}

		if err := rows.Err(); err != nil {
			http.Error(w, "Error processing rows", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(orders)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// GetOrderDetails handles fetching detailed information for a specific order
func GetOrderDetails(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		orderID := r.URL.Query().Get("order_id")
		if orderID == "" {
			http.Error(w, "Order ID is required", http.StatusBadRequest)
			return
		}

		db := dbConn()
		defer db.Close()

		var courier_id *int
		var order Order
		err := db.QueryRow("SELECT order_id, pickup_location, dropoff_location, package_details, status ,  created_at, updated_at, courier_id, user_id FROM `orders` WHERE order_id = ?", orderID).Scan(
			&order.ID,
			&order.PickupLocation,
			&order.DropoffLocation,
			&order.PackageDetails,
			&order.Status,
			&order.CreatedAt,
			&order.UpdatedAt,
			&courier_id,
			&order.UserID,
		)
		if courier_id != nil {
			order.CourierID = *courier_id
		} else {
			order.CourierID = 0
		}
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "Order not found", http.StatusNotFound)
				return
			}
			http.Error(w, "Error fetching order details", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(order)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// DeleteOrder handles the deletion of an order by ID
func DeleteOrder(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodDelete {
		orderIDStr := r.URL.Query().Get("order_id")
		if orderIDStr == "" {
			http.Error(w, "Order ID is required", http.StatusBadRequest)
			return
		}

		orderID, err := strconv.Atoi(orderIDStr)
		if err != nil {
			http.Error(w, "Invalid order ID", http.StatusBadRequest)
			return
		}

		db := dbConn()
		defer db.Close()

		var order Order
		err = db.QueryRow("SELECT order_id, status FROM `orders` WHERE order_id = ?", orderID).Scan(&order.ID, &order.Status)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "Order not found", http.StatusNotFound)
				return
			}
			// Log the error for further inspection
			log.Printf("Error fetching order: %v", err)
			http.Error(w, "Error fetching order", http.StatusInternalServerError)
			return
		}

		if order.Status != "Pending" {
			http.Error(w, "Cannot delete order: Order is not in Pending status", http.StatusConflict)
			return
		}

		// execute query
		_, err = db.Exec("DELETE FROM `orders` WHERE order_id = ?", orderID)
		if err != nil {
			log.Printf("Error deleting order: %v", err)
			http.Error(w, "Error deleting order", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// Courier Features

func getCourierOrders(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		courierID := r.URL.Query().Get("courier_id")
		if courierID == "" {
			http.Error(w, "Courier ID is required", http.StatusBadRequest)
			return
		}

		db := dbConn()
		defer db.Close()

		// Query to fetch all orders for the specified user
		rows, err := db.Query("SELECT order_id, pickup_location, dropoff_location, package_details, delivery_time, status, courier_id, created_at, updated_at, user_id FROM `orders` WHERE courier_id = ?", courierID)
		if err != nil {
			http.Error(w, "Error fetching orders", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var orders []Order

		// Loop through rows and scan each order's data into an Order struct
		for rows.Next() {
			var order Order
			var deliveryTime sql.NullString
			var courierID *int

			err := rows.Scan(
				&order.ID, &order.PickupLocation, &order.DropoffLocation,
				&order.PackageDetails, &deliveryTime, &order.Status,
				&courierID, &order.CreatedAt, &order.UpdatedAt, &order.UserID,
			)
			if err != nil {
				println(err.Error())
				http.Error(w, "Error scanning order data", http.StatusInternalServerError)
				return
			}

			// Handle nullable fields
			if deliveryTime.Valid {
				order.DeliveryTime = deliveryTime.String
			}
			//if courierID !=  {
			//	order.CourierID = int(courierID)
			//}
			if courierID != nil {
				order.CourierID = *courierID
			} else {
				order.CourierID = 0
			}

			orders = append(orders, order)
		}

		if err := rows.Err(); err != nil {
			http.Error(w, "Error processing rows", http.StatusInternalServerError)
			return
		}

		// Return orders as JSON
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(orders)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// updateOrderStatus handles updating the status of an order for current logged in courier
func updateOrderStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPut {
		var order Order

		err := json.NewDecoder(r.Body).Decode(&order)
		if err != nil {
			http.Error(w, "Invalid request payload", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		println(order.ID)
		println(order.Status)
		// Check for required fields
		if order.ID == 0 || order.Status == "" {
			http.Error(w, "Missing required fields", http.StatusBadRequest)
			return
		}

		db := dbConn()
		defer db.Close()

		// Prepare the SQL statement for updating the order status
		updForm, err := db.Prepare("UPDATE `orders` SET status = ? WHERE order_id = ? AND courier_id = ?")
		if err != nil {
			http.Error(w, "Error preparing query", http.StatusInternalServerError)
			return
		}
		defer updForm.Close()

		// Execute the prepared statement
		res, err := updForm.Exec(order.Status, order.ID, order.CourierID)
		if err != nil {
			http.Error(w, "Error updating order status", http.StatusInternalServerError)
			return
		}

		// Check if the order was found
		rowsAffected, err := res.RowsAffected()
		if err != nil {
			http.Error(w, "Error checking rows affected", http.StatusInternalServerError)
			return
		}
		if rowsAffected == 0 {
			http.Error(w, "Order not found or unauthorized", http.StatusNotFound)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "Order status updated successfully"})
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func declineOrder(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPut {
		orderIDStr := r.URL.Query().Get("order_id")
		if orderIDStr == "" {
			http.Error(w, "Order ID is required", http.StatusBadRequest)
			return
		}

		orderID, err := strconv.Atoi(orderIDStr)
		if err != nil {
			http.Error(w, "Invalid order ID", http.StatusBadRequest)
			return
		}

		db := dbConn()
		defer db.Close()

		// Prepare the SQL statement for updating the order status
		updForm, err := db.Prepare("UPDATE `orders` SET courier_id = NULL WHERE order_id = ?")
		if err != nil {
			http.Error(w, "Error preparing query", http.StatusInternalServerError)
			return
		}
		defer updForm.Close()

		// Execute the prepared statement
		res, err := updForm.Exec(orderID)
		if err != nil {
			http.Error(w, "Error updating order status", http.StatusInternalServerError)
			return
		}

		// Check if the order was found
		rowsAffected, err := res.RowsAffected()
		if err != nil {
			http.Error(w, "Error checking rows affected", http.StatusInternalServerError)
			return
		}
		if rowsAffected == 0 {
			http.Error(w, "Order not found", http.StatusNotFound)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "Order declined successfully"})
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func acceptOrder(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPut {
		var order Order
		orderID, err := strconv.Atoi(r.URL.Query().Get("order_id"))
		if err != nil {
			http.Error(w, "Invalid order ID", http.StatusBadRequest)
			return
		}
		order.ID = orderID
		println(order.ID)
		println(order.Status)
		// Check for required fields
		if order.ID == 0 {
			http.Error(w, "Missing required fields", http.StatusBadRequest)
			return
		}

		db := dbConn()
		// check whether the order exists
		err = db.QueryRow("SELECT order_id, status FROM `orders` WHERE order_id = ?", orderID).Scan(&order.ID, &order.Status)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "Order not found or unauthorized", http.StatusNotFound)
				return
			}
			http.Error(w, "Error fetching order details", http.StatusInternalServerError)
			return
		}

		// Prepare the SQL statement for updating the order status
		updForm, err := db.Prepare("UPDATE `orders` SET status = 'Accepted' WHERE order_id = ?")
		if err != nil {
			http.Error(w, "Error preparing query", http.StatusInternalServerError)
			return
		}
		defer updForm.Close()

		// Execute the prepared statement
		res, err := updForm.Exec(order.ID)
		if err != nil {
			println(err.Error())
			http.Error(w, "Error updating order status", http.StatusInternalServerError)
			return
		}

		// Check if the order was found
		rowsAffected, err := res.RowsAffected()
		if err != nil {
			http.Error(w, "Error checking rows affected", http.StatusInternalServerError)
			return
		}
		if rowsAffected == 0 {
			http.Error(w, "Order not found or unauthorized", http.StatusNotFound)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "Order status updated successfully"})
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func getAcceptedOrders(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		courierID := r.URL.Query().Get("courier_id")
		if courierID == "" {
			http.Error(w, "Courier ID is required", http.StatusBadRequest)
			return
		}

		db := dbConn()
		defer db.Close()

		// Query to fetch all orders for the specified user
		rows, err := db.Query("SELECT order_id, pickup_location, dropoff_location, package_details, delivery_time, status, courier_id, created_at, updated_at, user_id FROM `orders` WHERE courier_id = ? AND status != 'Pending' ", courierID)
		if err != nil {
			http.Error(w, "Error fetching orders", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var orders []Order

		// Loop through rows and scan each order's data into an Order struct
		for rows.Next() {
			var order Order
			var deliveryTime sql.NullString
			var courierID sql.NullInt64

			err := rows.Scan(
				&order.ID, &order.PickupLocation, &order.DropoffLocation,
				&order.PackageDetails, &deliveryTime, &order.Status,
				&courierID, &order.CreatedAt, &order.UpdatedAt, &order.UserID,
			)
			if err != nil {
				http.Error(w, "Error scanning order data", http.StatusInternalServerError)
				return
			}

			// Handle nullable fields
			if deliveryTime.Valid {
				order.DeliveryTime = deliveryTime.String
			}
			if courierID.Valid {
				order.CourierID = int(courierID.Int64)
			}

			orders = append(orders, order)
		}

		if err := rows.Err(); err != nil {
			http.Error(w, "Error processing rows", http.StatusInternalServerError)
			return
		}

		// Return orders as JSON
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(orders)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// Admin Features

func getOrders(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		db := dbConn()
		defer db.Close()

		// Query to fetch all orders
		rows, err := db.Query("SELECT order_id, pickup_location, dropoff_location, package_details, delivery_time, user_id, status, courier_id, created_at, updated_at FROM `orders`")
		if err != nil {
			http.Error(w, "Error fetching orders", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var orders []Order

		// Loop through rows and scan each order's data into an Order struct
		for rows.Next() {
			var order Order
			var deliveryTime sql.NullString
			var courierID sql.NullInt64

			err := rows.Scan(
				&order.ID, &order.PickupLocation, &order.DropoffLocation,
				&order.PackageDetails, &deliveryTime, &order.UserID,
				&order.Status, &courierID, &order.CreatedAt, &order.UpdatedAt,
			)
			if err != nil {
				http.Error(w, "Error scanning order data", http.StatusInternalServerError)
				return
			}

			// Handle nullable fields
			if deliveryTime.Valid {
				order.DeliveryTime = deliveryTime.String
			}
			if courierID.Valid {
				order.CourierID = int(courierID.Int64)
			}

			orders = append(orders, order)
		}

		if err := rows.Err(); err != nil {
			http.Error(w, "Error processing rows", http.StatusInternalServerError)
			return
		}

		// Return orders as JSON
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(orders)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func updateOrderStatusAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPut {
		var order Order

		err := json.NewDecoder(r.Body).Decode(&order)
		if err != nil {
			http.Error(w, "Invalid request payload", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		println(order.ID)
		println(order.Status)
		// Check for required fields
		if order.ID == 0 || order.Status == "" {
			http.Error(w, "Missing required fields", http.StatusBadRequest)
			return
		}

		db := dbConn()
		defer db.Close()

		// Prepare the SQL statement for updating the order status
		updForm, err := db.Prepare("UPDATE `orders` SET status = ? WHERE order_id = ?")
		if err != nil {
			http.Error(w, "Error preparing query", http.StatusInternalServerError)
			return
		}
		defer updForm.Close()

		// Execute the prepared statement
		res, err := updForm.Exec(order.Status, order.ID)
		if err != nil {
			println(err.Error())
			http.Error(w, "Error updating order status", http.StatusInternalServerError)
			return
		}

		// Check if the order was found
		rowsAffected, err := res.RowsAffected()
		if err != nil {
			http.Error(w, "Error checking rows affected", http.StatusInternalServerError)
			return
		}
		if rowsAffected == 0 {
			http.Error(w, "Order not found", http.StatusNotFound)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "Order status updated successfully"})
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func deleteOrderAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodDelete {
		orderIDStr := r.URL.Query().Get("order_id")
		if orderIDStr == "" {
			http.Error(w, "Order ID is required", http.StatusBadRequest)
			return
		}

		orderID, err := strconv.Atoi(orderIDStr)
		if err != nil {
			http.Error(w, "Invalid order ID", http.StatusBadRequest)
			return
		}

		db := dbConn()
		defer db.Close()

		// execute query
		_, err = db.Exec("DELETE FROM `orders` WHERE order_id = ?", orderID)
		if err != nil {
			log.Printf("Error deleting order: %v", err)
			http.Error(w, "Error deleting order", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func reassignCourier(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPut {
		var payload struct {
			OrderID   int    `json:"id"`
			CourierID string `json:"courier_id"`
		}

		err := json.NewDecoder(r.Body).Decode(&payload)
		if err != nil {
			http.Error(w, "Invalid request payload", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		// Check for required fields
		if payload.OrderID == 0 || payload.CourierID == "" {
			http.Error(w, "Missing required fields", http.StatusBadRequest)
			return
		}

		db := dbConn()
		defer db.Close()

		// Prepare the SQL statement for updating the order status
		updForm, err := db.Prepare("UPDATE `orders` SET courier_id = ? WHERE order_id = ?")
		if err != nil {
			http.Error(w, "Error preparing query", http.StatusInternalServerError)
			return
		}
		defer updForm.Close()

		// Execute the prepared statement
		res, err := updForm.Exec(payload.CourierID, payload.OrderID)
		if err != nil {
			http.Error(w, "Error updating order status", http.StatusInternalServerError)
			return
		}

		// Check if the order was found
		rowsAffected, err := res.RowsAffected()
		if err != nil {
			http.Error(w, "Error checking rows affected", http.StatusInternalServerError)
			return
		}
		if rowsAffected == 0 {
			http.Error(w, "Order not found", http.StatusNotFound)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "Courier reassigned successfully"})
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func getAllCouriers(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		db := dbConn()
		defer db.Close()

		// Query to fetch all orders
		rows, err := db.Query("SELECT courier_id, name, email, phone FROM `courier`")
		if err != nil {
			http.Error(w, "Error fetching couriers", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var couriers []User

		// Loop through rows and scan each order's data into an Order struct
		for rows.Next() {
			var courier User

			err := rows.Scan(
				&courier.ID, &courier.Username, &courier.Email, &courier.Phone,
			)
			if err != nil {
				http.Error(w, "Error scanning courier data", http.StatusInternalServerError)
				return
			}

			couriers = append(couriers, courier)
		}

		if err := rows.Err(); err != nil {
			http.Error(w, "Error processing rows", http.StatusInternalServerError)
			return
		}

		// Return orders as JSON
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(couriers)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
