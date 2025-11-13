import React from 'react';
import { Bar, Pie, Line } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
  PointElement,
  LineElement,
} from 'chart.js';

ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
  PointElement,
  LineElement,
);

const AttackTrends = ({ attackData, attacksOverTime }) => {
  if (
    !attackData ||
    !attackData.typeDistribution ||
    !attackData.ipDistribution ||
    !attacksOverTime
  ) {
    return <div>Loading attack trends...</div>;
  }

  // Attack Type Distribution (Pie Chart)
  const attackTypeData = {
    labels: Object.keys(attackData.typeDistribution),
    datasets: [
      {
        label: 'Attack Type Distribution',
        data: Object.values(attackData.typeDistribution),
        backgroundColor: [
          'rgba(255, 99, 132, 0.6)',
          'rgba(54, 162, 235, 0.6)',
          'rgba(255, 206, 86, 0.6)',
          'rgba(75, 192, 192, 0.6)',
          'rgba(153, 102, 255, 0.6)',
          'rgba(255, 159, 64, 0.6)',
          'rgba(100, 100, 100, 0.6)',
        ],
        borderColor: [
          'rgba(255, 99, 132, 1)',
          'rgba(54, 162, 235, 1)',
          'rgba(255, 206, 86, 1)',
          'rgba(75, 192, 192, 1)',
          'rgba(153, 102, 255, 1)',
          'rgba(255, 159, 64, 1)',
          'rgba(100, 100, 100, 1)',
        ],
        borderWidth: 1,
      },
    ],
  };

  const attackTypeOptions = {
    responsive: true,
    plugins: {
      legend: {
        position: 'right',
        labels: {
          color: '#fff',
        },
      },
      title: {
        display: true,
        text: 'Attack Type Distribution',
        color: '#fff',
      },
    },
  };

  // Top 10 Attacker IPs (Bar Graph)
  const topIpLabels = attackData.ipDistribution.map((item) => item[0]);
  const topIpValues = attackData.ipDistribution.map((item) => item[1]);

  const topIpData = {
    labels: topIpLabels,
    datasets: [
      {
        label: 'Number of Attacks',
        data: topIpValues,
        backgroundColor: 'rgba(75, 192, 192, 0.6)',
        borderColor: 'rgba(75, 192, 192, 1)',
        borderWidth: 1,
      },
    ],
  };

  const topIpOptions = {
    responsive: true,
    plugins: {
      legend: {
        position: 'top',
        labels: {
          color: '#fff',
        },
      },
      title: {
        display: true,
        text: 'Top 10 Attacker IPs',
        color: '#fff',
      },
    },
    scales: {
      x: {
        ticks: {
          color: '#fff',
        },
        grid: {
          color: 'rgba(255, 255, 255, 0.1)',
        },
      },
      y: {
        ticks: {
          color: '#fff',
        },
        grid: {
          color: 'rgba(255, 255, 255, 0.1)',
        },
      },
    },
  };

  // Attacks over Time (Line Chart)
  const sortedTimeLabels = Object.keys(attacksOverTime).sort();
  const attacksOverTimeData = {
    labels: sortedTimeLabels,
    datasets: [
      {
        label: 'Attacks per Hour',
        data: sortedTimeLabels.map((label) => attacksOverTime[label]),
        fill: false,
        borderColor: 'rgb(255, 159, 64)',
        tension: 0.1,
        pointBackgroundColor: '#fff',
        pointBorderColor: 'rgb(255, 159, 64)',
      },
    ],
  };

  const attacksOverTimeOptions = {
    responsive: true,
    plugins: {
      legend: {
        position: 'top',
        labels: {
          color: '#fff',
        },
      },
      title: {
        display: true,
        text: 'Attacks Over Time',
        color: '#fff',
      },
    },
    scales: {
      x: {
        ticks: {
          color: '#fff',
        },
        grid: {
          color: 'rgba(255, 255, 255, 0.1)',
        },
      },
      y: {
        ticks: {
          color: '#fff',
        },
        grid: {
          color: 'rgba(255, 255, 255, 0.1)',
        },
      },
    },
  };

  return (
    <div className="attack-trends-container">
      <h2>Attack Trends & Analytics</h2>
      <div className="chart-row">
        <div className="chart-item">
          <Pie data={attackTypeData} options={attackTypeOptions} />
        </div>
        <div className="chart-item">
          <Bar data={topIpData} options={topIpOptions} />
        </div>
      </div>
      <div className="chart-row">
        <div className="chart-item full-width">
          <Line data={attacksOverTimeData} options={attacksOverTimeOptions} />
        </div>
      </div>
    </div>
  );
};

export default AttackTrends;
