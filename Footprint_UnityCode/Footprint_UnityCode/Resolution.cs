using System.Collections;
using System.Collections.Generic;
using UnityEngine;

public class Resolution : MonoBehaviour
{
    //해상도 설정
    public int screenWidth = 800;
    public int screenHeight = 600;

    void Start()
    {
        ChangeResolution();
    }

    void ChangeResolution()
    {
        Screen.fullScreen = false;
        Screen.SetResolution(screenWidth, screenHeight, Screen.fullScreen);
    }
}
