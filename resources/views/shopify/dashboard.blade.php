<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Location Check App - Admin Dashboard</title>
  <style>
    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      font-family: "Inter", "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
      background: #f8f9fb;
      color: #333;
      min-height: 100vh;
      display: flex;
      justify-content: center;
      align-items: flex-start;
      padding: 40px 20px;
    }

    .container {
      background: #fff;
      border-radius: 12px;
      box-shadow: 0 6px 20px rgba(0, 0, 0, 0.06);
      width: 100%;
      /* max-width: 900px; */
      padding: 30px 40px;
      animation: fadeIn 0.5s ease-in-out;
    }

    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 30px;
    }

    .header h1 {
      font-size: 28px;
      color: #2c7be5;
    }

    .header .shop-name {
      font-size: 16px;
      color: #666;
    }

    .content {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 20px;
    }

    .card {
      background: #f1f3f7;
      padding: 20px;
      border-radius: 8px;
      text-align: center;
      transition: background 0.3s ease, box-shadow 0.3s ease;
    }

    .card:hover {
      background: #e7ebf3;
      box-shadow: 0 4px 10px rgba(0, 0, 0, 0.05);
    }

    .card h2 {
      font-size: 18px;
      margin-bottom: 10px;
      color: #2c7be5;
    }

    .card p {
      font-size: 14px;
      color: #555;
      margin-bottom: 15px;
    }

    .btn {
      background: #2c7be5;
      color: #fff;
      padding: 10px 20px;
      border-radius: 6px;
      text-decoration: none;
      font-size: 14px;
      font-weight: 500;
      display: inline-block;
      transition: background 0.3s ease;
    }

    .btn:hover {
      background: #1a68d1;
    }

    .footer {
      margin-top: 30px;
      text-align: center;
      font-size: 12px;
      color: #888;
    }

    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(10px); }
      to { opacity: 1; transform: translateY(0); }
    }
  </style>
</head>
<body>

  <div class="container">
    <div class="header">
      <h1>📍 Location Check App</h1>
      <div class="shop-name">Store: <strong>{{ $shop }}</strong></div>
    </div>

    <div class="card" style="display:none;">
      <h2>Danger Zone</h2>
      <p>This will permanently delete shop data from the database.</p>

      <form action="{{ route('shop.delete', $shop) }}" method="POST" onsubmit="return confirm('Are you sure you want to delete this shop? This cannot be undone.');">
          @csrf
          @method('DELETE')
          <button type="submit" class="btn" style="background:#e3342f;">Delete Shop Data</button>
      </form>
    </div>

    <div class="content">
      <div class="card">
        <h2>Manage Rules</h2>
        <p>Create and edit checkout location restrictions for your store.</p>
        <a href="#" class="btn">Go to Rules</a>
      </div>
      <div class="card">
        <h2>View Logs</h2>
        <p>See recent checkout attempts and blocked transactions.</p>
        <a href="#" class="btn">View Logs</a>
      </div>
      <div class="card">
        <h2>Settings</h2>
        <p>Configure app preferences, notifications, and more.</p>
        <a href="#" class="btn">App Settings</a>
      </div>
      <div class="card">
        <h2>Help & Support</h2>
        <p>Find documentation or contact our support team.</p>
        <a href="#" class="btn">Get Help</a>
      </div>
    </div>

    <div class="footer">
      &copy; {{ date('Y') }} Location Check App. All rights reserved.
    </div>
  </div>

</body>
</html>
