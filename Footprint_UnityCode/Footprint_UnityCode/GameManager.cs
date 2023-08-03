using System.Collections;
using System.Collections.Generic;
using UnityEngine;

public class GameManager : MonoBehaviour
{
    //시작화면
    public GameObject Cover;

    public void ClickButton()
    {
        Cover.SetActive(false);
    }
}