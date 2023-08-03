using System.Collections;
using System.Collections.Generic;
using System;
using System.IO;
using UnityEngine;

public class MovePlayer3 : MonoBehaviour
{
    private float xInit = 508f;
    private float yInit = 350f;

    private float xMax = 607f;
    private float yMax = 405f;

    private float speed = 10f;

    private string filePath = @"C:\network\Footprint_Player[3].txt";

    private float xValue;
    private float yValue;

    void Start()
    {
        transform.position = new Vector3(xInit, yInit, 0);
    }

    void Update()
    {
        UpdatePosition();
    }

    void UpdatePosition()
    {
        string line;
        System.IO.StreamReader reader = new System.IO.StreamReader(filePath);

        while ((line = reader.ReadLine()) != null)
        {
            //x, y 값 공백으로 분
            string[] xyPosition = line.Split(' ');

            //string to float
            if (float.TryParse(xyPosition[0], out xValue) && float.TryParse(xyPosition[1], out yValue))
            {

                xValue -= 208; //미니맵에 맞게 y값 조정
                yValue += 98; //미니맵에 맞게 y값 조정

                //x Maximum 제한
                if (xValue > xMax)
                {
                    xValue = xMax;
                }
                //y Maximum 제한
                if (yValue >= yMax)
                {
                    yValue = yMax;
                }

                //업데이트된 좌표값으로 오브젝트 이동
                Vector3 newPosition = new Vector3(xValue, yValue, 0);
                transform.position = Vector3.MoveTowards(transform.position, newPosition, speed);
            }
            else
            {
                Debug.LogError("Invalid Format.");
            }
        }
        reader.Close();
    }
}