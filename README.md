# Financial Management Application

A modern web application for tracking personal finances, managing transactions, and analyzing financial data.

## Features

### 1. Transaction Management
- Add new transactions with detailed information
- Support for both income and expense tracking
- Categorize transactions for better organization
- Multiple input methods:
  - Manual entry
  - Voice recording
  - Photo capture (receipt scanning)

### 2. Category Management
- Create custom categories for transactions
- Separate categories for income and expenses
- Easy category management through the dashboard

### 3. Financial Analytics
- Real-time financial statistics
- Total income tracking
- Total expense tracking
- Net amount calculation
- Interactive charts for financial trends
- Visual representation of financial data

### 4. User Dashboard
- Clean and intuitive interface
- Recent transactions list
- Category overview
- Financial summary cards
- Responsive design for all devices

## Technical Stack

### Frontend
- HTML5
- CSS3 (Bootstrap 5)
- JavaScript
- Chart.js for data visualization
- Modern web APIs (MediaRecorder, FileReader)

### Backend
- Python (Flask framework)
- SQLite/PostgreSQL database
- RESTful API endpoints

## Installation

1. Clone the repository:
```bash
git clone [repository-url]
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up the database:
```bash
flask db upgrade
```

4. Run the application:
```bash
flask run
```

## Usage

1. **Adding Transactions**
   - Navigate to the dashboard
   - Fill in the transaction details:
     - Amount
     - Type (Income/Expense)
     - Category
     - Description
   - Choose input method:
     - Manual entry
     - Voice recording
     - Photo capture

2. **Managing Categories**
   - Add new categories from the dashboard
   - Specify category type (Income/Expense)
   - View existing categories in the categories table

3. **Viewing Analytics**
   - Check financial summary cards for quick overview
   - View detailed charts in the analytics section
   - Monitor recent transactions

## API Endpoints

- `/add_transaction` - POST: Add new transaction
- `/process_voice` - POST: Process voice recordings
- `/process_photo` - POST: Process photo receipts
- `/add_category` - POST: Add new category

## Security Features

- User authentication
- Secure data transmission
- Input validation
- Error handling

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please open an issue in the GitHub repository or contact the development team. 

##  Group Members
- Martin Mutwiri Gachanja 
- Steve Ogolla Asumba 
- Dennis Amutsa 
- Simon Muriu Mbugua 
- Hannah Machocho 
- Liwa Watson Waswa
- Cynthia Ongwenyi

##  Group Members Emails
- mutwirigachanja1@gmail.com
- steveasumba@gmail.com
- amutsadennis@gmail.com
- muriumsimon6@gmail.com
- machochohannah5@gmail.com
- watsonliwa@yahoo.com
- onorah09@gmail.com
- ongwenyicynthia@gmail.com
- esibitaremmanuel316@gmail.com
